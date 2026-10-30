use clap::{ArgAction, Parser};
use env_logger::Env;
use log::{debug, info, warn};
use md5;
use pcap::{Capture, Error as PcapError, Linktype};
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum as ipv4_checksum};
use pnet::packet::ipv6::Ipv6Packet;
use serde::Serialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// CLI arguments for the experimental `rewrite` command.
#[derive(Parser, Debug)]
#[command(
    name = "rewrite",
    about = "Rewrite PCAP/PCAPNG files for deterministic replay (experimental)",
    arg_required_else_help = true
)]
pub struct RewriteCli {
    /// Input capture to rewrite
    #[arg(short, long, value_name = "PCAP")]
    pub input: PathBuf,

    /// Optional output capture; defaults to <input>_rewritten.<ext>
    #[arg(short, long, value_name = "PCAP")]
    pub output: Option<PathBuf>,

    /// Optional manifest file (JSON) describing actions taken
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,

    /// Topology description to guide address remapping
    #[arg(long, value_name = "TOPOLOGY")]
    pub topology: Option<PathBuf>,

    /// Verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,

    /// If set, compute plan only and skip writing outputs
    #[arg(long)]
    pub dry_run: bool,

    /// Emit progress every N packets (0 disables progress logs)
    #[arg(long, value_name = "N", default_value_t = 1_000_000)]
    pub progress_every: u64,

    /// Stop after N packets (useful for large-capture benchmarking)
    #[arg(long, value_name = "N")]
    pub max_packets: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RewriteConfig {
    pub input: PathBuf,
    pub output: PathBuf,
    pub manifest: Option<PathBuf>,
    pub topology: Option<PathBuf>,
    pub dry_run: bool,
    pub progress_every: u64,
    pub max_packets: Option<u64>,
}

impl RewriteConfig {
    pub fn from_cli(cli: &RewriteCli) -> Self {
        let output = cli
            .output
            .clone()
            .unwrap_or_else(|| default_output_path(&cli.input));

        Self {
            input: cli.input.clone(),
            output,
            manifest: cli.manifest.clone(),
            topology: cli.topology.clone(),
            dry_run: cli.dry_run,
            progress_every: cli.progress_every,
            max_packets: cli.max_packets,
        }
    }
}

#[derive(Debug, Serialize)]
struct RewriteManifest {
    input: String,
    output: String,
    topology: Option<String>,
    dry_run: bool,
    status: String,
    notes: Vec<String>,
    stats: Option<RewriteStats>,
}

impl RewriteManifest {
    fn from_config(config: &RewriteConfig) -> Self {
        Self {
            input: config.input.display().to_string(),
            output: config.output.display().to_string(),
            topology: config.topology.as_ref().map(|p| p.display().to_string()),
            dry_run: config.dry_run,
            status: "pending".to_string(),
            notes: vec![
                "Preliminary rewrite pipeline executed; advanced transformations pending."
                    .to_string(),
            ],
            stats: None,
        }
    }

    fn write_if_requested(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::File::create(path)?;
        let json = serde_json::to_vec_pretty(self)
            .unwrap_or_else(|_| b"{\"status\":\"invalid\"}".to_vec());
        file.write_all(&json)?;
        Ok(())
    }
}

/// Raise `len` to `caplen` when a record claims fewer bytes on the wire than
/// were captured. Some corpus captures carry such records (e.g. caplen 606 >
/// len 110), and gopherCap refuses the whole file on the first one after
/// scanning all of it — 80 minutes for a 16 GB capture. The bytes present are
/// the truth. Returns whether the header was changed.
pub fn clamp_record_len(header: &mut pcap::PacketHeader) -> bool {
    if header.len < header.caplen {
        header.len = header.caplen;
        true
    } else {
        false
    }
}

#[derive(Debug, Serialize, Clone, Default)]
struct RewriteStats {
    packets_total: u64,
    packets_converted: u64,
    packets_remapped: u64,
    packets_ipv6_converted: u64,
    /// Records whose caplen exceeded len in the source; len was raised to
    /// caplen so gopherCap (which rejects the whole file on the first such
    /// record after scanning all of it) accepts the output.
    packets_len_clamped: u64,
    capture_duration_seconds: Option<f64>,
    input_format: String,
    output_format: String,
    linktype_in: String,
    linktype_out: String,
    edge_hosts_used: Vec<String>,
}

#[derive(Debug, Default)]
struct RewriteOutcome {
    stats: RewriteStats,
    warnings: Vec<String>,
}

/// Write buffer for the rewritten capture.
///
/// libpcap's `pcap_dump` issues two `fwrite` calls per record through a stdio
/// buffer sized to the filesystem block size (4 KiB here), so a 1 GB capture
/// costs ~250k `write(2)` calls. This writer packs the identical classic-pcap
/// byte stream into buffers of this size instead.
const WRITE_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Number of write buffers in flight (one being filled, the rest queued for or
/// held by the writer thread). Bounds memory at `WRITE_BUFFER_BYTES * this`.
const WRITE_BUFFER_COUNT: usize = 3;

/// Classic-pcap savefile writer, byte-compatible with `pcap_dump`.
///
/// Two changes against the libpcap dumper it replaces, neither of which alters
/// the emitted bytes:
///
/// * Records are packed into 4 MiB buffers instead of libpcap's two `fwrite`
///   calls per record through a block-sized stdio buffer.
/// * Full buffers are handed to a writer thread, so the `write(2)` syscalls
///   overlap with reading and rewriting the next records rather than stalling
///   the single worker. Buffers are recycled back, so steady-state allocation
///   is zero.
///
/// Header fields are written in host byte order exactly as libpcap does (the
/// magic then reads back as `0xa1b2c3d4` on the writing host), the snaplen is
/// the 65535 that `Capture::dead` installs, and record headers carry the 32-bit
/// truncation of the timestamp that `pcap_dump` performs.
struct PcapWriter {
    buf: Vec<u8>,
    full: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    recycled: std::sync::mpsc::Receiver<Vec<u8>>,
    worker: Option<std::thread::JoinHandle<Result<(), std::io::Error>>>,
}

impl PcapWriter {
    fn create(path: &Path, linktype: Linktype) -> Result<Self, std::io::Error> {
        let mut file = fs::File::create(path)?;
        let mut header = [0u8; 24];
        header[0..4].copy_from_slice(&0xa1b2_c3d4u32.to_ne_bytes());
        header[4..6].copy_from_slice(&2u16.to_ne_bytes()); // version major
        header[6..8].copy_from_slice(&4u16.to_ne_bytes()); // version minor
        header[8..12].copy_from_slice(&0i32.to_ne_bytes()); // thiszone
        header[12..16].copy_from_slice(&0u32.to_ne_bytes()); // sigfigs
        header[16..20].copy_from_slice(&65_535u32.to_ne_bytes()); // snaplen
        header[20..24].copy_from_slice(&(linktype.0 as u32).to_ne_bytes());
        file.write_all(&header)?;

        let (full_tx, full_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(WRITE_BUFFER_COUNT);
        let (recycle_tx, recycle_rx) = std::sync::mpsc::channel::<Vec<u8>>();

        let worker = std::thread::Builder::new()
            .name("pcap-writer".to_string())
            .spawn(move || -> Result<(), std::io::Error> {
                let mut result = Ok(());
                for mut chunk in full_rx {
                    if result.is_ok()
                        && let Err(e) = file.write_all(&chunk)
                    {
                        result = Err(e);
                    }
                    chunk.clear();
                    // A closed recycle channel just means the producer is gone.
                    let _ = recycle_tx.send(chunk);
                }
                result
            })?;

        Ok(Self {
            buf: Vec::with_capacity(WRITE_BUFFER_BYTES),
            full: Some(full_tx),
            recycled: recycle_rx,
            worker: Some(worker),
        })
    }

    #[inline]
    fn write(&mut self, header: &pcap::PacketHeader, data: &[u8]) -> Result<(), std::io::Error> {
        let mut record = [0u8; 16];
        record[0..4].copy_from_slice(&(header.ts.tv_sec as u32).to_ne_bytes());
        record[4..8].copy_from_slice(&(header.ts.tv_usec as u32).to_ne_bytes());
        record[8..12].copy_from_slice(&(data.len() as u32).to_ne_bytes());
        record[12..16].copy_from_slice(&header.len.to_ne_bytes());
        self.buf.extend_from_slice(&record);
        self.buf.extend_from_slice(data);
        if self.buf.len() >= WRITE_BUFFER_BYTES {
            self.dispatch()?;
        }
        Ok(())
    }

    /// Hand the filled buffer to the writer thread and take a recycled one.
    fn dispatch(&mut self) -> Result<(), std::io::Error> {
        let sender = match &self.full {
            Some(sender) => sender,
            None => return Ok(()),
        };
        // Take a spare buffer first: allocate until the pool is at its cap,
        // then block on a recycled one, which is what bounds memory.
        let spare = match self.recycled.try_recv() {
            Ok(buf) => buf,
            Err(std::sync::mpsc::TryRecvError::Empty) => Vec::with_capacity(WRITE_BUFFER_BYTES),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(std::io::Error::other("pcap writer thread stopped"));
            }
        };
        let filled = std::mem::replace(&mut self.buf, spare);
        if sender.send(filled).is_err() {
            return Err(std::io::Error::other("pcap writer thread stopped"));
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), std::io::Error> {
        if !self.buf.is_empty() {
            self.dispatch()?;
        }
        self.full = None; // close the queue so the worker drains and exits
        match self.worker.take() {
            Some(handle) => handle
                .join()
                .map_err(|_| std::io::Error::other("pcap writer thread panicked"))?,
            None => Ok(()),
        }
    }
}

impl Drop for PcapWriter {
    fn drop(&mut self) {
        self.full = None;
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

/// Fold a 64-bit ones-complement accumulator down to the final 16-bit value.
///
/// Identical result to `pnet_packet::util::finalize_checksum`, which folds a
/// 32-bit accumulator; folding is associative so a wider accumulator is safe.
#[inline]
fn fold_checksum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !(sum as u16)
}

/// Sum 16-bit big-endian words, eight bytes at a time.
///
/// Byte-for-byte equivalent to `pnet_packet::util::sum_be_words(data, usize::MAX)`
/// (no skipped word) but reads 4 bytes per add instead of 2, so the compiler can
/// keep the loop in registers. Callers zero the checksum field first, which is
/// exactly what pnet's `skipword` argument emulates.
///
/// Overflow: each 8-byte chunk contributes at most 2^33, so a 64-bit accumulator
/// cannot overflow for any capture record (even a 4 GiB one).
#[inline]
fn sum_be_words_fast(data: &[u8]) -> u64 {
    let mut sum: u64 = 0;
    let (chunks, rem) = data.as_chunks::<8>();
    for c in chunks {
        let hi = u32::from_be_bytes([c[0], c[1], c[2], c[3]]) as u64;
        let lo = u32::from_be_bytes([c[4], c[5], c[6], c[7]]) as u64;
        sum += hi + lo;
    }
    let mut i = 0;
    while i + 2 <= rem.len() {
        sum += u16::from_be_bytes([rem[i], rem[i + 1]]) as u64;
        i += 2;
    }
    if i < rem.len() {
        // Odd trailing byte is treated as the high half of a word, as pnet does.
        sum += (rem[i] as u64) << 8;
    }
    sum
}

/// TCP/UDP checksum over an IPv4 pseudo-header plus `data`.
///
/// Equivalent to `pnet_packet::tcp::ipv4_checksum` / `udp::ipv4_checksum` when the
/// segment's own checksum field has already been zeroed.
#[inline]
fn transport_checksum_ipv4(data: &[u8], src: &Ipv4Addr, dst: &Ipv4Addr, proto: u8) -> u16 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u64 = 0;
    sum += (((s[0] as u64) << 8) | s[1] as u64) + (((s[2] as u64) << 8) | s[3] as u64);
    sum += (((d[0] as u64) << 8) | d[1] as u64) + (((d[2] as u64) << 8) | d[3] as u64);
    sum += proto as u64;
    sum += data.len() as u64;
    sum += sum_be_words_fast(data);
    fold_checksum(sum)
}

/// Rewrite the transport checksum of an IPv4 payload in place.
///
/// `payload` is the IPv4 payload slice exactly as pnet would hand it to
/// `MutableTcpPacket`/`MutableUdpPacket`, so the summed extent is unchanged.
#[inline]
fn set_transport_checksum_ipv4(
    payload: &mut [u8],
    protocol: IpNextHeaderProtocol,
    src: &Ipv4Addr,
    dst: &Ipv4Addr,
) {
    // Offset of the checksum field and the minimum packet size pnet enforces
    // before it hands out a mutable view.
    let (offset, min_len) = match protocol {
        IpNextHeaderProtocols::Udp => (6usize, 8usize),
        IpNextHeaderProtocols::Tcp => (16usize, 20usize),
        _ => return,
    };
    if payload.len() < min_len {
        return;
    }
    payload[offset] = 0;
    payload[offset + 1] = 0;
    let checksum = transport_checksum_ipv4(payload, src, dst, protocol.0);
    payload[offset..offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn default_output_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("pcap");
    let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("pcap");
    parent.join(format!("{}_rewritten.{}", stem, ext))
}

/// UDP/TCP ports reserved for INT reports to the collectors (9080 + collector
/// index; env/controller/int_pipeline.py). The controller forwards ANY packet
/// with these destination ports to a collector, which parses it as telemetry,
/// so a replayed packet must never carry one.
const RESERVED_INT_PORTS: std::ops::RangeInclusive<u16> = 9080..=9089;
/// Replacement offset for a reserved port (9080 -> 10080, ...).
const RESERVED_PORT_SHIFT: u16 = 1000;
/// DSCP that the P4 parser treats as an INT shim (p4src/include/int_definitions.p4).
const INT_DSCP: u8 = 0x17;

/// Move TCP/UDP source and destination ports out of the INT report range.
/// `transport` starts at the TCP/UDP header. Returns true when a port changed;
/// the caller recomputes the checksum.
fn guard_reserved_ports(transport: &mut [u8], protocol: IpNextHeaderProtocol) -> bool {
    if !matches!(
        protocol,
        IpNextHeaderProtocols::Tcp | IpNextHeaderProtocols::Udp
    ) || transport.len() < 4
    {
        return false;
    }
    let mut changed = false;
    for off in [0usize, 2] {
        let port = u16::from_be_bytes([transport[off], transport[off + 1]]);
        if RESERVED_INT_PORTS.contains(&port) {
            let moved = port + RESERVED_PORT_SHIFT;
            transport[off..off + 2].copy_from_slice(&moved.to_be_bytes());
            changed = true;
        }
    }
    changed
}

struct AddressRewriter {
    /// Ordered list of unique edge host addresses (group A followed by group B).
    edge_ips: Vec<Ipv4Addr>,
    /// Edge hosts attached to INT source switches (e.g., h1/h2).
    group_a: Vec<Ipv4Addr>,
    /// Edge hosts attached to background switches (e.g., h3/h4).
    group_b: Vec<Ipv4Addr>,
    mapping_v4: HashMap<Ipv4Addr, Ipv4Addr>,
    mapping_v6: HashMap<Ipv6Addr, Ipv4Addr>,
}

impl AddressRewriter {
    fn new(topology_path: Option<&Path>) -> Self {
        let mut group_a: Vec<Ipv4Addr> = Vec::new();
        let mut group_b: Vec<Ipv4Addr> = Vec::new();

        if let Some(path) = topology_path
            && let Ok(contents) = fs::read_to_string(path)
            && let Ok(json) = serde_json::from_str::<Value>(&contents)
            && let Some(nodes) = json.get("nodes").and_then(|n| n.as_array())
        {
            for node in nodes {
                let node_type = node.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if node_type != "host" {
                    continue;
                }
                // Topologies write "id" (env/topo.py); older files used "name".
                let name = node
                    .get("id")
                    .or_else(|| node.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                // INT collectors are never traffic endpoints: replayed packets
                // addressed to them were ingested as telemetry (2026-10-30).
                let is_collector = node
                    .get("isCollector")
                    .and_then(|c| c.as_bool())
                    .unwrap_or(false)
                    || name.starts_with("hc");
                if is_collector {
                    continue;
                }
                let ip_str = node.get("ip").and_then(|i| i.as_str()).unwrap_or("");
                if let Some(ip) = parse_ipv4(ip_str) {
                    match name {
                        "h1" | "h2" => group_a.push(ip),
                        "h3" | "h4" => group_b.push(ip),
                        _ => {
                            // fall back based on subnet heuristic
                            if ip.octets()[2] == 1 {
                                group_a.push(ip);
                            } else {
                                group_b.push(ip);
                            }
                        }
                    }
                }
            }
        }

        if group_a.is_empty() || group_b.is_empty() {
            group_a = vec![Ipv4Addr::new(10, 0, 1, 1), Ipv4Addr::new(10, 0, 1, 2)];
            group_b = vec![Ipv4Addr::new(10, 0, 5, 3), Ipv4Addr::new(10, 0, 5, 4)];
        }

        let mut edge_ips = Vec::new();
        edge_ips.extend(group_a.iter().copied());
        edge_ips.extend(group_b.iter().copied());

        debug!(
            "AddressRewriter initialized | edge_ips={:?} group_a={:?} group_b={:?}",
            edge_ips, group_a, group_b
        );

        Self {
            edge_ips,
            group_a,
            group_b,
            mapping_v4: HashMap::new(),
            mapping_v6: HashMap::new(),
        }
    }

    fn rewrite_ipv4(&mut self, ethernet: &mut MutableEthernetPacket) -> Result<bool, String> {
        let mut ipv4_packet = MutableIpv4Packet::new(ethernet.payload_mut())
            .ok_or_else(|| "Malformed IPv4 payload".to_string())?;

        let original_src = ipv4_packet.get_source();
        let original_dst = ipv4_packet.get_destination();

        let mapped_src = self.map_ipv4_with_preference(original_src, None);
        let mapped_dst = self.map_ipv4_with_preference(original_dst, Some(mapped_src));

        let mut changed = false;
        if mapped_src != original_src {
            ipv4_packet.set_source(mapped_src);
            changed = true;
        }
        if mapped_dst != original_dst {
            ipv4_packet.set_destination(mapped_dst);
            changed = true;
        }
        // A captured DSCP equal to the INT DSCP would make the switch parse the
        // packet as INT; keep ECN, clear the DSCP.
        let tos = ipv4_packet.get_dscp();
        if tos == INT_DSCP {
            ipv4_packet.set_dscp(0);
            changed = true;
        }
        // Only the first fragment carries the transport header.
        if ipv4_packet.get_fragment_offset() == 0 {
            let protocol = ipv4_packet.get_next_level_protocol();
            if guard_reserved_ports(ipv4_packet.payload_mut(), protocol) {
                changed = true;
            }
        }

        if changed {
            ipv4_packet.set_checksum(0);
            let checksum = ipv4_checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);

            let protocol = ipv4_packet.get_next_level_protocol();
            set_transport_checksum_ipv4(
                ipv4_packet.payload_mut(),
                protocol,
                &mapped_src,
                &mapped_dst,
            );

            return Ok(true);
        }

        Ok(false)
    }

    fn map_ipv4_with_preference(
        &mut self,
        ip: Ipv4Addr,
        prefer_other_of: Option<Ipv4Addr>,
    ) -> Ipv4Addr {
        if let Some(mapped) = self.mapping_v4.get(&ip) {
            return *mapped;
        }
        if self.edge_ips.is_empty() {
            return ip;
        }
        let ip_string = ip.to_string();
        let digest = md5::compute(ip_string.as_bytes());
        let mut idx = (u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize)
            % self.edge_ips.len();

        if let Some(prefer_ip) = prefer_other_of
            && let Some(prefer_idx) = self
                .edge_ips
                .iter()
                .position(|&candidate| candidate == prefer_ip)
        {
            let prefer_in_group_a = prefer_idx < self.group_a.len();
            let (group_start, group_len) = if prefer_in_group_a {
                (self.group_a.len(), self.group_b.len())
            } else {
                (0, self.group_a.len())
            };

            if group_len > 0 {
                let offset = idx % group_len;
                idx = group_start + offset;
            }
        }

        let mapped = self.edge_ips[idx.min(self.edge_ips.len() - 1)];
        self.mapping_v4.insert(ip, mapped);
        mapped
    }

    fn map_ipv6_with_preference(
        &mut self,
        ip: Ipv6Addr,
        prefer_other_of: Option<Ipv4Addr>,
    ) -> Ipv4Addr {
        if self.edge_ips.is_empty() {
            return Ipv4Addr::new(10, 0, 1, 1);
        }

        if let Some(&mapped) = self.mapping_v6.get(&ip) {
            return mapped;
        }

        if let Some(mapped_ipv4) = ip.to_ipv4_mapped()
            && self.edge_ips.contains(&mapped_ipv4)
        {
            self.mapping_v6.insert(ip, mapped_ipv4);
            return mapped_ipv4;
        }

        let seed = Self::ipv6_seed(ip);
        let pool = prefer_other_of
            .and_then(|prefer| self.pool_for_preference(prefer))
            .unwrap_or_else(|| self.default_ipv6_pool());

        let mut candidate = self.select_candidate(pool, seed, prefer_other_of);

        if self.mapping_v6.values().any(|&used| used == candidate) {
            candidate = self
                .first_unused(&self.edge_ips, prefer_other_of)
                .unwrap_or(candidate);
        }

        debug!(
            "map_ipv6_with_preference | ip={} prefer={:?} mapped={}",
            ip, prefer_other_of, candidate
        );

        self.mapping_v6.insert(ip, candidate);
        candidate
    }

    fn pool_for_preference(&self, prefer: Ipv4Addr) -> Option<&[Ipv4Addr]> {
        if self.group_a.contains(&prefer) && !self.group_b.is_empty() {
            Some(&self.group_b)
        } else if self.group_b.contains(&prefer) && !self.group_a.is_empty() {
            Some(&self.group_a)
        } else {
            None
        }
    }

    fn default_ipv6_pool(&self) -> &[Ipv4Addr] {
        if !self.group_a.is_empty() {
            &self.group_a
        } else {
            &self.edge_ips
        }
    }

    fn select_candidate(&self, pool: &[Ipv4Addr], seed: u32, avoid: Option<Ipv4Addr>) -> Ipv4Addr {
        if pool.is_empty() {
            return avoid.unwrap_or_else(|| Ipv4Addr::new(10, 0, 1, 1));
        }

        let len = pool.len();
        let start = (seed as usize) % len;

        if let Some(candidate) =
            pool.iter()
                .copied()
                .cycle()
                .skip(start)
                .take(len)
                .find(|candidate| {
                    Some(*candidate) != avoid
                        && !self.mapping_v6.values().any(|&used| used == *candidate)
                })
        {
            return candidate;
        }

        self.first_unused(pool, avoid)
            .or_else(|| self.first_unused(&self.edge_ips, avoid))
            .unwrap_or_else(|| pool[start])
    }

    fn first_unused(&self, pool: &[Ipv4Addr], avoid: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        pool.iter().copied().find(|candidate| {
            Some(*candidate) != avoid && !self.mapping_v6.values().any(|&used| used == *candidate)
        })
    }

    fn ipv6_seed(ip: Ipv6Addr) -> u32 {
        let octets = ip.octets();
        let md5_digest = md5::compute(octets);
        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(octets);
        let sha1_digest = sha1_hasher.finalize();
        let md5_part =
            u32::from_be_bytes([md5_digest[0], md5_digest[1], md5_digest[2], md5_digest[3]]);
        let sha1_part = u32::from_be_bytes([
            sha1_digest[0],
            sha1_digest[1],
            sha1_digest[2],
            sha1_digest[3],
        ]);
        md5_part ^ sha1_part
    }
}

/// Translate an IPv6 frame into the equivalent IPv4 frame, writing into `out`.
///
/// Writes straight into the caller's reusable buffer: the earlier version
/// allocated three `Vec`s per packet (payload copy, IPv4 header, output frame).
/// The emitted bytes are unchanged.
fn rewrite_ipv6_packet_into(
    rewriter: &mut AddressRewriter,
    frame: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), String> {
    // `frame` has already been accepted by `EthernetPacket::new`, so the 14-byte
    // header is present and `frame[14..]` is what pnet calls the payload.
    let ipv6_packet =
        Ipv6Packet::new(&frame[14..]).ok_or_else(|| "Malformed IPv6 payload".to_string())?;

    let src_v6 = ipv6_packet.get_source();
    let dst_v6 = ipv6_packet.get_destination();

    let mapped_src = rewriter.map_ipv6_with_preference(src_v6, None);
    let mapped_dst = rewriter.map_ipv6_with_preference(dst_v6, Some(mapped_src));

    let next_header = ipv6_packet.get_next_header();
    let hop_limit = ipv6_packet.get_hop_limit();
    let payload = ipv6_packet.payload();
    let payload_len = payload.len();

    match next_header {
        IpNextHeaderProtocols::Udp if payload_len < 8 => {
            return Err("Malformed UDP payload".to_string());
        }
        IpNextHeaderProtocols::Tcp if payload_len < 20 => {
            return Err("Malformed TCP payload".to_string());
        }
        _ => {}
    }

    out.clear();
    out.reserve(34 + payload_len);
    out.extend_from_slice(&frame[0..12]); // destination then source MAC
    out.extend_from_slice(&[0x08, 0x00]); // EtherTypes::Ipv4
    out.resize(34, 0); // zeroed IPv4 header, filled in below
    out.extend_from_slice(payload);

    match next_header {
        IpNextHeaderProtocols::Udp | IpNextHeaderProtocols::Tcp => {
            guard_reserved_ports(&mut out[34..], next_header);
            set_transport_checksum_ipv4(&mut out[34..], next_header, &mapped_src, &mapped_dst);
        }
        IpNextHeaderProtocols::Icmpv6 if payload_len >= 4 => {
            let icmp = &mut out[34..];
            icmp[0] = match icmp[0] {
                128 => 8,
                129 => 0,
                other => other,
            };
            icmp[2] = 0;
            icmp[3] = 0;
            if let Some(mut icmp_packet) = pnet::packet::icmp::MutableIcmpPacket::new(icmp) {
                icmp_packet.set_checksum(0);
                let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
                icmp_packet.set_checksum(checksum);
            }
        }
        _ => {}
    }

    let total_length = (20 + payload_len) as u16;
    let mut ipv4_packet = MutableIpv4Packet::new(&mut out[14..34])
        .ok_or_else(|| "Failed to allocate IPv4 header".to_string())?;
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(total_length);
    ipv4_packet.set_identification(0);
    ipv4_packet.set_flags(0);
    ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_ttl(hop_limit);
    ipv4_packet.set_next_level_protocol(map_next_header(next_header));
    ipv4_packet.set_source(mapped_src);
    ipv4_packet.set_destination(mapped_dst);
    ipv4_packet.set_checksum(0);
    let checksum = ipv4_checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);

    Ok(())
}

fn map_next_header(nh: IpNextHeaderProtocol) -> IpNextHeaderProtocol {
    if nh == IpNextHeaderProtocols::Icmpv6 {
        IpNextHeaderProtocols::Icmp
    } else {
        nh
    }
}

pub fn run(cli: RewriteCli) -> Result<(), Box<dyn Error>> {
    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let mut builder = env_logger::Builder::from_env(Env::default().default_filter_or(log_level));
    let _ = builder.try_init();

    let config = RewriteConfig::from_cli(&cli);
    info!("pcap-sleuth rewrite (experimental) invoked");
    info!("Input: {}", config.input.display());
    info!("Output: {}", config.output.display());
    if let Some(topology) = &config.topology {
        info!("Topology: {}", topology.display());
    }
    if config.progress_every > 0 {
        info!("Progress logging every {} packets", config.progress_every);
    }
    if let Some(limit) = config.max_packets {
        info!("Packet processing capped at {} packets", limit);
    }
    if cli.dry_run {
        info!("Dry-run enabled; no files will be emitted");
    }

    let outcome = perform_rewrite(&config)?;

    if !outcome.warnings.is_empty() {
        for warning in &outcome.warnings {
            warn!("{}", warning);
        }
    }

    if let Some(manifest_path) = &config.manifest {
        let mut manifest = RewriteManifest::from_config(&config);
        manifest.status = "success".to_string();
        manifest.stats = Some(outcome.stats.clone());
        manifest.notes = if outcome.warnings.is_empty() {
            vec!["Rewrite completed with no warnings.".to_string()]
        } else {
            outcome.warnings.clone()
        };
        manifest.write_if_requested(manifest_path)?;
        info!("Manifest written to {}", manifest_path.display());
    }

    info!(
        "Rewrite completed | packets_total={} linktype_out={} dry_run={}",
        outcome.stats.packets_total, outcome.stats.linktype_out, config.dry_run
    );

    Ok(())
}

fn perform_rewrite(config: &RewriteConfig) -> Result<RewriteOutcome, Box<dyn Error>> {
    if !config.input.exists() {
        return Err(format!("Input capture not found: {}", config.input.display()).into());
    }

    let input_format = detect_capture_format(&config.input)?;
    let input_size = fs::metadata(&config.input)?.len();
    let mut capture = Capture::from_file(&config.input)?;
    let input_linktype = capture.get_datalink();
    let mut address_rewriter = AddressRewriter::new(config.topology.as_deref());

    info!(
        "Starting rewrite | input={} size_bytes={} format={:?} linktype_in={:?}",
        config.input.display(),
        input_size,
        input_format,
        input_linktype
    );

    if config.dry_run {
        let mut packets_total = 0_u64;
        let mut first_timestamp: Option<f64> = None;
        let mut last_timestamp: Option<f64> = None;
        let start = Instant::now();
        while let Ok(packet) = capture.next_packet() {
            packets_total += 1;
            let timestamp =
                packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
            first_timestamp.get_or_insert(timestamp);
            last_timestamp = Some(timestamp);

            if config.progress_every > 0 && packets_total % config.progress_every == 0 {
                let elapsed = start.elapsed().as_secs_f64().max(0.001);
                let rate = packets_total as f64 / elapsed;
                info!(
                    "Dry-run progress | packets={} elapsed={:.1}s rate={:.0} pkt/s",
                    packets_total, elapsed, rate
                );
            }

            if let Some(limit) = config.max_packets
                && packets_total >= limit
            {
                break;
            }
        }

        let elapsed = start.elapsed().as_secs_f64().max(0.001);
        let rate = packets_total as f64 / elapsed;

        return Ok(RewriteOutcome {
            stats: RewriteStats {
                packets_total,
                packets_converted: 0,
                packets_remapped: 0,
                packets_ipv6_converted: 0,
                packets_len_clamped: 0,
                capture_duration_seconds: first_timestamp
                    .zip(last_timestamp)
                    .map(|(first, last)| (last - first).max(0.0)),
                input_format: input_format.clone(),
                output_format: format!("dry-run ({:?})", input_linktype),
                linktype_in: format!("{:?}", input_linktype),
                linktype_out: format!("{:?}", input_linktype),
                edge_hosts_used: Vec::new(),
            },
            warnings: vec![
                "Dry-run mode: output capture not written".to_string(),
                format!("Dry-run throughput: {:.0} pkt/s over {:.1}s", rate, elapsed),
            ],
        });
    }

    if let Some(parent) = config.output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let output_linktype = match input_linktype {
        Linktype(113) => Linktype(1),
        other => other,
    };

    if config.output.to_str().is_none() {
        return Err("Output path must be valid UTF-8".into());
    }
    let mut writer = PcapWriter::create(&config.output, output_linktype)?;

    let mut packets_total = 0_u64;
    let mut packets_converted = 0_u64;
    let mut packets_remapped = 0_u64;
    let mut packets_ipv6_converted = 0_u64;
    let mut packets_len_clamped = 0_u64;
    let mut first_timestamp: Option<f64> = None;
    let mut last_timestamp: Option<f64> = None;
    let mut warnings = Vec::new();
    let start = Instant::now();
    // Frame buffers reused for every record; `scratch` receives SLL/IPv6
    // conversions and is then swapped in.
    let mut data: Vec<u8> = Vec::with_capacity(65_536);
    let mut scratch: Vec<u8> = Vec::with_capacity(65_536);

    loop {
        match capture.next_packet() {
            Ok(packet) => {
                packets_total += 1;
                let timestamp =
                    packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
                first_timestamp.get_or_insert(timestamp);
                last_timestamp = Some(timestamp);
                // Reusable frame buffers: no per-packet heap allocation.
                data.clear();
                data.extend_from_slice(packet.data);
                let mut header = *packet.header;

                if input_linktype == Linktype(113) {
                    match convert_sll_to_ethernet_into(&data, &mut scratch) {
                        Ok(()) => {
                            if scratch.len() != data.len() {
                                packets_converted += 1;
                            }
                            header.caplen = scratch.len() as u32;
                            header.len = scratch.len() as u32;
                            std::mem::swap(&mut data, &mut scratch);
                        }
                        Err(e) => {
                            warnings.push(format!(
                                "SLL conversion failed for packet {}: {} (writing original frame)",
                                packets_total, e
                            ));
                        }
                    }
                }

                let is_ipv6 = EthernetPacket::new(&data)
                    .is_some_and(|view| view.get_ethertype() == EtherTypes::Ipv6);
                if is_ipv6 {
                    match rewrite_ipv6_packet_into(&mut address_rewriter, &data, &mut scratch) {
                        Ok(()) => {
                            packets_ipv6_converted += 1;
                            header.caplen = scratch.len() as u32;
                            header.len = scratch.len() as u32;
                            std::mem::swap(&mut data, &mut scratch);
                        }
                        Err(e) => warnings.push(format!(
                            "IPv6 rewrite failed for packet {}: {} (packet left unchanged)",
                            packets_total, e
                        )),
                    }
                }

                if let Some(mut ethernet_packet) = MutableEthernetPacket::new(&mut data)
                    && ethernet_packet.get_ethertype() == EtherTypes::Ipv4
                {
                    match address_rewriter.rewrite_ipv4(&mut ethernet_packet) {
                        Ok(true) => packets_remapped += 1,
                        Ok(false) => {}
                        Err(e) => warnings.push(format!(
                            "IPv4 remap failed for packet {}: {} (packet left unchanged)",
                            packets_total, e
                        )),
                    }
                }

                if clamp_record_len(&mut header) {
                    packets_len_clamped += 1;
                }
                writer.write(&header, &data)?;

                if config.progress_every > 0 && packets_total % config.progress_every == 0 {
                    let elapsed = start.elapsed().as_secs_f64().max(0.001);
                    let rate = packets_total as f64 / elapsed;
                    info!(
                        "Rewrite progress | packets={} remapped={} ipv6_converted={} elapsed={:.1}s rate={:.0} pkt/s",
                        packets_total, packets_remapped, packets_ipv6_converted, elapsed, rate
                    );
                }

                if let Some(limit) = config.max_packets
                    && packets_total >= limit
                {
                    warnings.push(format!(
                        "Reached max-packets limit ({}) after rewriting {} packets",
                        limit, packets_total
                    ));
                    break;
                }
            }
            Err(PcapError::NoMorePackets) => break,
            Err(PcapError::TimeoutExpired) => {
                warnings.push(format!(
                    "Capture read timed out after {} packets; partial output written.",
                    packets_total
                ));
                warn!(
                    "Capture read timed out after {} packets for {}",
                    packets_total,
                    config.input.display()
                );
                break;
            }
            Err(err) => {
                warnings.push(format!(
                    "Capture read failed after {} packets: {}",
                    packets_total, err
                ));
                warn!(
                    "Capture read failed after {} packets for {}: {}",
                    packets_total,
                    config.input.display(),
                    err
                );
                break;
            }
        }
    }

    writer.finish()?;

    let mut outcome = RewriteOutcome {
        stats: RewriteStats {
            packets_total,
            packets_converted,
            packets_remapped,
            packets_ipv6_converted,
            packets_len_clamped,
            capture_duration_seconds: first_timestamp
                .zip(last_timestamp)
                .map(|(first, last)| (last - first).max(0.0)),
            input_format: input_format.clone(),
            output_format: format!("pcap ({:?})", output_linktype),
            linktype_in: format!("{:?}", input_linktype),
            linktype_out: format!("{:?}", output_linktype),
            edge_hosts_used: Vec::new(),
        },
        warnings,
    };

    if outcome.stats.packets_total == 0 {
        outcome
            .warnings
            .push("Input capture yielded zero packets; output may be invalid.".to_string());
    }

    let mut edge_hosts_used: HashSet<Ipv4Addr> =
        address_rewriter.mapping_v4.values().copied().collect();
    edge_hosts_used.extend(address_rewriter.mapping_v6.values().copied());
    let mut edge_hosts_vec: Vec<String> = edge_hosts_used
        .into_iter()
        .map(|ip| ip.to_string())
        .collect();
    edge_hosts_vec.sort();
    outcome.stats.edge_hosts_used = edge_hosts_vec;

    if input_linktype == Linktype(113) && packets_converted == 0 {
        outcome
            .warnings
            .push("Detected SLL link-type but no frames were converted".to_string());
    }

    Ok(outcome)
}

fn detect_capture_format(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = fs::File::open(path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    let format = match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] => "pcap (be)".to_string(),
        [0xd4, 0xc3, 0xb2, 0xa1] => "pcap (le)".to_string(),
        [0xa1, 0xb2, 0x3c, 0x4d] => "pcap-ns (be)".to_string(),
        [0x4d, 0x3c, 0xb2, 0xa1] => "pcap-ns (le)".to_string(),
        [0x0a, 0x0d, 0x0d, 0x0a] => "pcapng".to_string(),
        other => format!(
            "unknown (magic 0x{:02x}{:02x}{:02x}{:02x})",
            other[0], other[1], other[2], other[3]
        ),
    };
    Ok(format)
}

/// Convert a LINUX_SLL frame to Ethernet, writing into the caller's buffer.
fn convert_sll_to_ethernet_into(data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
    if data.len() < 16 {
        return Err("SLL frame too short".to_string());
    }

    let mut proto = u16::from_be_bytes([data[14], data[15]]);
    if proto == 0 {
        proto = 0x0800; // default to IPv4 when SLL header omits ethertype
    }
    let payload = &data[16..];

    let (src_mac, dst_mac) = derive_macs(payload);

    out.clear();
    out.reserve(14 + payload.len());
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&proto.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

fn derive_macs(payload: &[u8]) -> ([u8; 6], [u8; 6]) {
    const DEFAULT_SRC: [u8; 6] = [0x00, 0x04, 0x00, 0x01, 0x00, 0x01];
    const DEFAULT_DST: [u8; 6] = [0x00, 0x04, 0x00, 0x05, 0x00, 0x04];

    if let Some(ip) = Ipv4Packet::new(payload) {
        let src = mac_from_ipv4(ip.get_source().octets(), DEFAULT_SRC);
        let dst = mac_from_ipv4(ip.get_destination().octets(), DEFAULT_DST);
        return (src, dst);
    }

    if let Some(ip6) = Ipv6Packet::new(payload) {
        let src = mac_from_ipv6(ip6.get_source().octets(), DEFAULT_SRC);
        let dst = mac_from_ipv6(ip6.get_destination().octets(), DEFAULT_DST);
        return (src, dst);
    }

    (DEFAULT_SRC, DEFAULT_DST)
}

fn mac_from_ipv4(addr: [u8; 4], default: [u8; 6]) -> [u8; 6] {
    if addr.iter().all(|&b| b == 0) {
        return default;
    }
    [0x00, 0x04, addr[0], addr[1], addr[2], addr[3]]
}

fn mac_from_ipv6(addr: [u8; 16], default: [u8; 6]) -> [u8; 6] {
    if addr.iter().all(|&b| b == 0) {
        return default;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&addr[10..16]);
    mac
}

fn parse_ipv4(candidate: &str) -> Option<Ipv4Addr> {
    let addr = candidate.split('/').next().unwrap_or(candidate).trim();
    addr.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::{Capture, Linktype};
    use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum as ipv4_checksum};
    use pnet::packet::udp::{MutableUdpPacket, ipv4_checksum as udp_ipv4_checksum};
    use pnet::util::MacAddr;
    use std::error::Error;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use tempfile::tempdir;

    /// The hand-written 64-bit accumulator must agree with pnet's 32-bit,
    /// two-bytes-at-a-time reference for every length and alignment, otherwise
    /// rewritten captures would differ from earlier runs.
    #[test]
    fn fast_transport_checksum_matches_pnet() {
        use pnet::packet::tcp::{MutableTcpPacket, ipv4_checksum as tcp_ipv4_checksum};
        use pnet::packet::udp::{MutableUdpPacket, ipv4_checksum as udp_ipv4_checksum};

        let src = Ipv4Addr::new(10, 0, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 5, 4);
        // Deterministic pseudo-random payloads over every length that exercises
        // the 8-byte fast path, the 2-byte tail and the odd trailing byte.
        let mut state: u32 = 0x1234_5678;
        let mut next = move || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        };
        for len in 8..=200usize {
            let mut udp: Vec<u8> = (0..len).map(|_| next()).collect();
            udp[6] = 0;
            udp[7] = 0;
            let reference = {
                let pkt = MutableUdpPacket::new(&mut udp).expect("udp view");
                udp_ipv4_checksum(&pkt.to_immutable(), &src, &dst)
            };
            let fast = transport_checksum_ipv4(&udp, &src, &dst, IpNextHeaderProtocols::Udp.0);
            assert_eq!(reference, fast, "udp length {}", len);

            if len >= 20 {
                let mut tcp: Vec<u8> = (0..len).map(|_| next()).collect();
                tcp[16] = 0;
                tcp[17] = 0;
                let reference = {
                    let pkt = MutableTcpPacket::new(&mut tcp).expect("tcp view");
                    tcp_ipv4_checksum(&pkt.to_immutable(), &src, &dst)
                };
                let fast = transport_checksum_ipv4(&tcp, &src, &dst, IpNextHeaderProtocols::Tcp.0);
                assert_eq!(reference, fast, "tcp length {}", len);
            }
        }
    }

    #[test]
    fn default_output_keeps_extension() {
        let base = PathBuf::from("captures/sample.pcapng");
        let derived = default_output_path(&base);
        assert!(derived.ends_with("sample_rewritten.pcapng"));
    }

    #[test]
    fn manifest_written_when_requested() -> Result<(), Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("input.pcap");
        fs::write(&input, minimal_pcap_header())?;
        let manifest = tmp.path().join("manifest.json");

        let cli = RewriteCli {
            input: input.clone(),
            output: None,
            manifest: Some(manifest.clone()),
            topology: None,
            verbose: 0,
            dry_run: true,
            progress_every: 0,
            max_packets: None,
        };

        run(cli)?;

        let contents = fs::read_to_string(&manifest)?;
        assert!(contents.contains("\"status\""));
        assert!(contents.contains("success"));
        assert!(contents.contains("packets_total"));
        assert!(contents.contains("capture_duration_seconds"));

        Ok(())
    }

    #[test]
    fn copies_input_when_not_dry_run() -> Result<(), Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("sample.pcap");
        let data = minimal_pcap_with_packet()?;
        fs::write(&input, &data)?;

        let cli = RewriteCli {
            input: input.clone(),
            output: None,
            manifest: None,
            topology: None,
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
        };

        run(cli)?;

        let output = tmp.path().join("sample_rewritten.pcap");
        assert!(output.exists());
        let mut out_cap = Capture::from_file(&output)?;
        assert_eq!(out_cap.get_datalink(), Linktype(1));
        let packet = out_cap
            .next_packet()
            .expect("expected single packet in rewritten capture");
        let eth = EthernetPacket::new(packet.data).expect("valid ethernet frame");
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);
        let ipv4 = Ipv4Packet::new(eth.payload()).expect("valid ipv4 payload");
        let mapped_src = ipv4.get_source();
        let mapped_dst = ipv4.get_destination();
        assert_ne!(mapped_src, Ipv4Addr::new(192, 0, 2, 1));
        assert_ne!(mapped_dst, Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(mapped_src.octets()[0], 10);
        assert_eq!(mapped_dst.octets()[0], 10);

        Ok(())
    }

    #[test]
    fn clamps_records_whose_caplen_exceeds_len() -> Result<(), Box<dyn Error>> {
        // Some corpus captures carry records with caplen > len; gopherCap
        // refuses the whole file on the first one. The rewriter must emit
        // len >= caplen and count what it clamped.
        let tmp = tempdir()?;
        let input = tmp.path().join("badlen.pcap");
        let mut data = minimal_pcap_with_packet()?;
        // record header follows the 24-byte file header: ts_sec, ts_usec, caplen, len
        let caplen = u32::from_le_bytes(data[32..36].try_into()?);
        assert!(caplen > 1, "fixture must carry a packet");
        let bogus_len = caplen - 1;
        data[36..40].copy_from_slice(&bogus_len.to_le_bytes());
        fs::write(&input, &data)?;
        let manifest = tmp.path().join("manifest.json");
        let cli = RewriteCli {
            input: input.clone(),
            output: None,
            manifest: Some(manifest.clone()),
            topology: None,
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
        };
        run(cli)?;
        let output = tmp.path().join("badlen_rewritten.pcap");
        let mut out_cap = Capture::from_file(&output)?;
        let packet = out_cap.next_packet().expect("one packet");
        assert!(
            packet.header.len >= packet.header.caplen,
            "len {} < caplen {}",
            packet.header.len,
            packet.header.caplen
        );
        let manifest_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest)?)?;
        assert_eq!(manifest_json["stats"]["packets_len_clamped"], 1);
        Ok(())
    }

    #[test]
    fn rewrites_ipv6_packets_to_ipv4() -> Result<(), Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("ipv6.pcap");
        let data = minimal_ipv6_pcap()?;
        fs::write(&input, &data)?;

        let manifest = tmp.path().join("manifest.json");

        let cli = RewriteCli {
            input: input.clone(),
            output: None,
            manifest: Some(manifest.clone()),
            topology: None,
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
        };

        run(cli)?;

        let output = tmp.path().join("ipv6_rewritten.pcap");
        assert!(output.exists());
        let mut out_cap = Capture::from_file(&output)?;
        let packet = out_cap
            .next_packet()
            .expect("expected single packet after rewrite");
        let ethernet = EthernetPacket::new(packet.data).expect("valid frame");
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Ipv4);
        let ipv4 = Ipv4Packet::new(ethernet.payload()).expect("valid ipv4 payload");
        assert_eq!(ipv4.get_version(), 4);
        assert_eq!(ipv4.get_header_length(), 5);
        assert_eq!(ipv4.get_next_level_protocol(), IpNextHeaderProtocols::Udp);
        assert_eq!(ipv4.get_ttl(), 64);
        let src = ipv4.get_source();
        let dst = ipv4.get_destination();
        let allowed = [
            Ipv4Addr::new(10, 0, 1, 1),
            Ipv4Addr::new(10, 0, 1, 2),
            Ipv4Addr::new(10, 0, 5, 3),
            Ipv4Addr::new(10, 0, 5, 4),
        ];
        assert!(allowed.contains(&src));
        assert!(allowed.contains(&dst));
        assert_ne!(src, dst);

        let manifest_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(manifest)?)?;
        assert_eq!(manifest_json["stats"]["packets_ipv6_converted"], 1);
        assert_eq!(manifest_json["stats"]["capture_duration_seconds"], 0.0);

        Ok(())
    }

    fn minimal_pcap_header() -> Vec<u8> {
        let mut header = Vec::with_capacity(24);
        header.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        header.extend_from_slice(&[0x02, 0x00]);
        header.extend_from_slice(&[0x04, 0x00]);
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        header.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]);
        header.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        header
    }

    fn minimal_pcap_with_packet() -> Result<Vec<u8>, Box<dyn Error>> {
        let mut frame = vec![0u8; 14 + 20 + 8];
        let src_ip = Ipv4Addr::new(192, 0, 2, 1);
        let dst_ip = Ipv4Addr::new(198, 51, 100, 2);

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            ethernet.set_destination(MacAddr::broadcast());
            ethernet.set_source(MacAddr::new(0x00, 0x04, 0x00, 0x00, 0x00, 0x01));
            ethernet.set_ethertype(EtherTypes::Ipv4);

            {
                let mut ipv4 = MutableIpv4Packet::new(ethernet.payload_mut()).unwrap();
                ipv4.set_version(4);
                ipv4.set_header_length(5);
                ipv4.set_total_length(28);
                ipv4.set_ttl(64);
                ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                ipv4.set_source(src_ip);
                ipv4.set_destination(dst_ip);
                ipv4.set_checksum(0);

                {
                    let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).unwrap();
                    udp.set_source(1234);
                    udp.set_destination(5678);
                    udp.set_length(8);
                    udp.set_checksum(0);
                    let checksum = udp_ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip);
                    udp.set_checksum(checksum);
                }

                let checksum = ipv4_checksum(&ipv4.to_immutable());
                ipv4.set_checksum(checksum);
            }
        }

        let frame_len = frame.len() as u32;
        let mut bytes = minimal_pcap_header();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // ts sec
        bytes.extend_from_slice(&0u32.to_le_bytes()); // ts usec
        bytes.extend_from_slice(&frame_len.to_le_bytes());
        bytes.extend_from_slice(&frame_len.to_le_bytes());
        bytes.extend_from_slice(&frame);
        Ok(bytes)
    }

    fn minimal_ipv6_pcap() -> Result<Vec<u8>, Box<dyn Error>> {
        let mut frame = vec![0u8; 14 + 40 + 8];
        let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        {
            let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
            ethernet.set_destination(MacAddr::broadcast());
            ethernet.set_source(MacAddr::new(0x00, 0x04, 0x00, 0x00, 0x00, 0x02));
            ethernet.set_ethertype(EtherTypes::Ipv6);

            {
                use pnet::packet::ipv6::MutableIpv6Packet;
                let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
                ipv6.set_version(6);
                ipv6.set_payload_length(8);
                ipv6.set_next_header(IpNextHeaderProtocols::Udp);
                ipv6.set_hop_limit(64);
                ipv6.set_source(src_ip);
                ipv6.set_destination(dst_ip);

                {
                    let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).unwrap();
                    udp.set_source(2000);
                    udp.set_destination(4000);
                    udp.set_length(8);
                    udp.set_checksum(0);
                    let checksum =
                        pnet::packet::udp::ipv6_checksum(&udp.to_immutable(), &src_ip, &dst_ip);
                    udp.set_checksum(checksum);
                }
            }
        }

        let frame_len = frame.len() as u32;
        let mut bytes = minimal_pcap_header();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&frame_len.to_le_bytes());
        bytes.extend_from_slice(&frame_len.to_le_bytes());
        bytes.extend_from_slice(&frame);
        Ok(bytes)
    }

    /// The topology env/topo.py writes: hosts keyed by "id", collectors flagged.
    fn topology_with_collectors(dir: &std::path::Path) -> PathBuf {
        let topo = serde_json::json!({"nodes": [
            {"id": "s1", "type": "switch"},
            {"id": "h1", "type": "host", "ip": "10.0.1.1/24"},
            {"id": "h2", "type": "host", "ip": "10.0.1.2/24"},
            {"id": "h3", "type": "host", "ip": "10.0.5.3/24"},
            {"id": "h4", "type": "host", "ip": "10.0.5.4/24"},
            {"id": "hc1", "type": "host", "isCollector": true, "ip": "10.0.2.1/24"},
            {"id": "hc2", "type": "host", "isCollector": true, "ip": "10.0.3.1/24"},
            {"id": "hc3", "type": "host", "isCollector": true, "ip": "10.0.4.1/24"}
        ]});
        let path = dir.join("topology.json");
        fs::write(&path, serde_json::to_vec(&topo).unwrap()).unwrap();
        path
    }

    /// 2026-10-30: the pool read "name" while topologies write "id", so every
    /// host fell to the subnet heuristic and the INT collectors became replay
    /// destinations; the collector then ingested replayed packets as telemetry.
    #[test]
    fn collectors_are_never_in_the_address_pool() {
        let tmp = tempdir().unwrap();
        let rw = AddressRewriter::new(Some(&topology_with_collectors(tmp.path())));
        let collectors = [
            Ipv4Addr::new(10, 0, 2, 1),
            Ipv4Addr::new(10, 0, 3, 1),
            Ipv4Addr::new(10, 0, 4, 1),
        ];
        assert_eq!(
            rw.group_a,
            vec![Ipv4Addr::new(10, 0, 1, 1), Ipv4Addr::new(10, 0, 1, 2)]
        );
        assert_eq!(
            rw.group_b,
            vec![Ipv4Addr::new(10, 0, 5, 3), Ipv4Addr::new(10, 0, 5, 4)]
        );
        assert!(rw.edge_ips.iter().all(|ip| !collectors.contains(ip)));
    }

    #[test]
    fn no_original_address_maps_onto_a_collector() {
        let tmp = tempdir().unwrap();
        let mut rw = AddressRewriter::new(Some(&topology_with_collectors(tmp.path())));
        for i in 0..2000u32 {
            let src = Ipv4Addr::from(0xC000_0000u32.wrapping_add(i.wrapping_mul(2_654_435_761)));
            let dst = Ipv4Addr::from(0x0A00_0000u32.wrapping_add(i.wrapping_mul(40_503)));
            let ms = rw.map_ipv4_with_preference(src, None);
            let md = rw.map_ipv4_with_preference(dst, Some(ms));
            for m in [ms, md] {
                assert!(
                    m.octets()[2] == 1 || m.octets()[2] == 5,
                    "mapped onto {}",
                    m
                );
            }
        }
    }

    /// A captured port in the INT report range would be forwarded to a collector
    /// by the controller's catch-all rule; a captured INT DSCP would be parsed as
    /// an INT shim. Both are rewritten, and the checksums stay valid.
    #[test]
    fn reserved_int_ports_and_dscp_are_rewritten() {
        let tmp = tempdir().unwrap();
        let mut rw = AddressRewriter::new(Some(&topology_with_collectors(tmp.path())));
        let mut frame = vec![0u8; 14 + 20 + 8];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
            let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(28);
            ip.set_ttl(64);
            ip.set_dscp(INT_DSCP);
            ip.set_ecn(1);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(Ipv4Addr::new(8, 8, 8, 8));
            ip.set_destination(Ipv4Addr::new(192, 168, 7, 9));
            let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
            udp.set_source(53);
            udp.set_destination(9080);
            udp.set_length(8);
        }
        let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
        assert!(rw.rewrite_ipv4(&mut eth).unwrap());
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        assert_eq!(ip.get_dscp(), 0, "INT DSCP cleared");
        assert_eq!(ip.get_ecn(), 1, "ECN kept");
        assert_eq!(ip.get_checksum(), ipv4_checksum(&ip));
        let udp = pnet::packet::udp::UdpPacket::new(ip.payload()).unwrap();
        assert_eq!(
            udp.get_source(),
            53,
            "service ports outside the range are kept"
        );
        assert_eq!(udp.get_destination(), 10080);
        assert_eq!(
            udp.get_checksum(),
            udp_ipv4_checksum(&udp, &ip.get_source(), &ip.get_destination())
        );
    }
}
