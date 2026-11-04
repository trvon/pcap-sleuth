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

    /// Per-episode variation seed. Salts the address mapping and shifts
    /// ephemeral ports (>= 32768) by a seed-derived offset; both are recorded in
    /// the manifest. Absent: the deterministic, unsalted mapping of earlier runs.
    #[arg(long, value_name = "SEED")]
    pub seed: Option<u64>,

    /// Keep only a window of this many capture-seconds (replayed at native
    /// speed by the caller). The window start is density-aware (>= min_density_ratio of
    /// median rate, or densest, inside attack span if specified). Start, packets inside
    /// window, and rule are recorded in the manifest.
    #[arg(long, value_name = "SECONDS")]
    pub window_seconds: Option<f64>,

    /// Optional labelled attack start timestamp (seconds, relative or absolute).
    #[arg(long, value_name = "SECONDS")]
    pub attack_start: Option<f64>,

    /// Optional labelled attack end timestamp (seconds, relative or absolute).
    #[arg(long, value_name = "SECONDS")]
    pub attack_end: Option<f64>,

    /// Minimum window packet rate ratio relative to median rate (default 0.10)
    #[arg(long, value_name = "RATIO", default_value_t = 0.10)]
    pub min_density_ratio: f64,

    /// Minimum packets in the selected window (default 200). A window with fewer is
    /// widened symmetrically (clamped to the capture) until it holds N or the whole capture.
    #[arg(long, value_name = "N", default_value_t = 200)]
    pub min_window_packets: u64,

    /// Loop the selected window's packets back to back, each pass shifted by the pass
    /// span plus the median inter-packet gap, until the output spans --window-seconds
    /// (capped at 1000 passes). Default on; only acts when --window-seconds is set.
    #[arg(long, value_name = "BOOL", default_value_t = true, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub loop_fill: bool,

    /// Cap on loop-fill passes (default 1000). When the cap, not the window, stops the loop the
    /// output is shorter than --window-seconds and the manifest sets loop_capped.
    #[arg(long, value_name = "N", default_value_t = 1000)]
    pub max_loop_passes: u64,

    /// How a window selects packets. `flow-start` (default) keeps only packets of flows whose
    /// first packet in the capture lies inside the window (so handshakes are present);
    /// `time` keeps every packet whose timestamp lies inside the window.
    #[arg(long, value_enum, default_value = "flow-start")]
    pub window_anchor: WindowAnchor,

    /// With `--window-anchor flow-start`: packets of kept flows are retained up to this many
    /// seconds past the window end (default 5).
    #[arg(long, value_name = "SECONDS", default_value_t = 5.0)]
    pub flow_grace_seconds: f64,

    /// Widening to reach --min-window-packets may grow a window only up to this many seconds
    /// (default 2 * --window-seconds). A window still short of the minimum falls back to the
    /// densest --window-seconds window, which loop-fill repeats (window_rule `densest_loop`).
    #[arg(long, value_name = "SECONDS")]
    pub max_window_span: Option<f64>,
}

/// Window packet-selection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum WindowAnchor {
    FlowStart,
    Time,
}

impl WindowAnchor {
    fn name(self) -> &'static str {
        match self {
            WindowAnchor::FlowStart => "flow_start",
            WindowAnchor::Time => "time",
        }
    }
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
    pub seed: Option<u64>,
    pub window_seconds: Option<f64>,
    pub attack_start: Option<f64>,
    pub attack_end: Option<f64>,
    pub min_density_ratio: f64,
    pub min_window_packets: u64,
    pub loop_fill: bool,
    pub max_loop_passes: u64,
    pub window_anchor: WindowAnchor,
    pub flow_grace_seconds: f64,
    pub max_window_span: Option<f64>,
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
            seed: cli.seed,
            window_seconds: cli.window_seconds,
            attack_start: cli.attack_start,
            attack_end: cli.attack_end,
            min_density_ratio: cli.min_density_ratio,
            min_window_packets: cli.min_window_packets,
            loop_fill: cli.loop_fill,
            max_loop_passes: cli.max_loop_passes,
            window_anchor: cli.window_anchor,
            flow_grace_seconds: cli.flow_grace_seconds,
            max_window_span: cli.max_window_span,
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
    /// Variation seed in force (None: unsalted mapping, ports untouched).
    seed: Option<u64>,
    /// Offset added (mod 32768) to ephemeral ports >= 32768 under `seed`.
    ephemeral_port_offset: Option<u16>,
    /// Requested window length (capture seconds), when windowing was asked for.
    window_seconds: Option<f64>,
    /// Window start relative to the first packet (seconds).
    window_start_seconds: Option<f64>,
    /// Full source capture span (seconds), measured before windowing.
    source_duration_seconds: Option<f64>,
    /// Packets dropped because they fell outside the window.
    packets_outside_window: u64,
    /// Packets inside the chosen window.
    window_packets: Option<u64>,
    /// Rule used to select the window (e.g. "density_aware", "densest_fallback", "whole_capture").
    window_rule: Option<String>,
    /// Passes of the window emitted (1 = no looping).
    loop_passes: u64,
    /// Configured cap on loop passes.
    max_loop_passes: u64,
    /// True when the loop stopped because of the cap, not because the window was filled.
    loop_capped: bool,
    /// Packets of the final loop pass dropped because they fell at or after the window end.
    loop_truncated_packets: u64,
    /// Span (first to last packet) of the emitted output, seconds.
    output_span_seconds: Option<f64>,
    /// Window packet-selection rule in force ("flow_start" or "time"), when windowing.
    window_anchor: Option<String>,
    /// Distinct flows with at least one packet written (flow-start anchoring only).
    flows_kept: u64,
    /// Distinct flows dropped because they began before the window.
    flows_dropped_partial: u64,
    /// Packets of those flows that fell inside the window's time range.
    packets_dropped_partial: u64,
    /// True when the input's timestamps were not in order (measured only when windowing).
    input_unsorted: bool,
    /// Records whose timestamp is earlier than the record before them (windowing only).
    input_out_of_order_packets: u64,
}

/// Bidirectional flow key: protocol plus the unordered pair of (address, port) endpoints.
type FlowKey = (u8, ([u8; 16], u16), ([u8; 16], u16));

/// Flow key of a raw frame (Ethernet, optionally 802.1Q, or Linux cooked); None for non-IP.
fn flow_key(linktype: Linktype, data: &[u8]) -> Option<FlowKey> {
    let (mut off, mut ethertype) = if linktype == Linktype(113) {
        if data.len() < 16 {
            return None;
        }
        (16, u16::from_be_bytes([data[14], data[15]]))
    } else {
        if data.len() < 14 {
            return None;
        }
        (14, u16::from_be_bytes([data[12], data[13]]))
    };
    while (ethertype == 0x8100 || ethertype == 0x88a8) && data.len() >= off + 4 {
        ethertype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        off += 4;
    }
    let ip = data.get(off..)?;
    let (proto, src, dst, l4): (u8, [u8; 16], [u8; 16], Option<&[u8]>) = match ethertype {
        0x0800 => {
            if ip.len() < 20 || ip[0] >> 4 != 4 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s[..4].copy_from_slice(&ip[12..16]);
            d[..4].copy_from_slice(&ip[16..20]);
            let frag = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
            let l4 = if frag == 0 { ip.get(ihl..) } else { None };
            (ip[9], s, d, l4)
        }
        0x86dd => {
            if ip.len() < 40 || ip[0] >> 4 != 6 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&ip[8..24]);
            d.copy_from_slice(&ip[24..40]);
            (ip[6], s, d, ip.get(40..))
        }
        _ => return None,
    };
    let (sp, dp) = match (proto, l4) {
        (6 | 17, Some(l4)) if l4.len() >= 4 => (
            u16::from_be_bytes([l4[0], l4[1]]),
            u16::from_be_bytes([l4[2], l4[3]]),
        ),
        _ => (0, 0),
    };
    let a = (src, sp);
    let b = (dst, dp);
    Some(if a <= b { (proto, a, b) } else { (proto, b, a) })
}

/// Timestamp of the first packet of every IP flow in the capture.
fn flow_first_seen(path: &Path) -> Result<HashMap<FlowKey, f64>, Box<dyn Error>> {
    let mut cap = Capture::from_file(path)?;
    let linktype = cap.get_datalink();
    let mut first: HashMap<FlowKey, f64> = HashMap::new();
    while let Ok(packet) = cap.next_packet() {
        let t = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        if let Some(k) = flow_key(linktype, packet.data) {
            let e = first.entry(k).or_insert(t);
            if t < *e {
                *e = t;
            }
        }
    }
    Ok(first)
}

fn header_micros(h: &pcap::PacketHeader) -> i64 {
    (h.ts.tv_sec as i64) * 1_000_000 + (h.ts.tv_usec as i64)
}

/// Emit the buffered first pass again, back to back (pass k shifted by k * (pass span +
/// median inter-packet gap), within-pass timing exact), until the next pass would start at or
/// after `t0 + target_span` seconds; at most 1000 passes in all. Packets whose shifted time is
/// at or after `t0 + target_span` are dropped (final pass truncated). Returns (passes, last
/// emitted timestamp, truncated packets).
fn emit_loop_passes(
    writer: &mut PcapWriter,
    buf: &[(pcap::PacketHeader, Vec<u8>)],
    target_span: f64,
    max_passes: u64,
) -> Result<(u64, Option<f64>, u64, bool), Box<dyn Error>> {
    // Timestamps need not be monotonic in file order (shuffled captures): the pass extent
    // is its min..max, not first..last record, or a pass whose last record is earlier than
    // its first would get span 0 and the loop would never reach the window.
    let mut sorted: Vec<i64> = buf.iter().map(|(h, _)| header_micros(h)).collect();
    sorted.sort_unstable();
    let t0 = sorted[0];
    let t_last = sorted[sorted.len() - 1];
    let pass_span = t_last - t0;
    let mut gaps: Vec<i64> = sorted.windows(2).map(|w| w[1] - w[0]).collect();
    gaps.sort_unstable();
    let median_gap = if gaps.is_empty() {
        0
    } else {
        gaps[gaps.len() / 2]
    };
    // A pass whose packets share one timestamp has span 0; without a floor every pass would
    // stack at one instant.
    let min_shift = (10_000.0_f64)
        .max(target_span * 1_000_000.0 / (buf.len().max(1) as f64))
        .ceil() as i64;
    let shift = (pass_span + median_gap).max(min_shift);
    let target_us = (target_span * 1_000_000.0).ceil() as i64;
    let mut passes = 1_u64;
    let mut last = t_last;
    // A first pass that already fills the window up to one packet gap (the window is
    // half-open, so a dense capture ends one gap short of window_seconds) is not looped.
    if pass_span + median_gap >= target_us {
        return Ok((1, None, 0, false));
    }
    let mut truncated = 0_u64;
    while passes < max_passes.max(1) && (passes as i64) * shift < target_us {
        let offset = (passes as i64) * shift;
        for (h, d) in buf {
            let mut nh = *h;
            let t = header_micros(h) + offset;
            if t - t0 >= target_us {
                truncated += 1;
                continue;
            }
            last = last.max(t);
            nh.ts.tv_sec = (t / 1_000_000) as _;
            nh.ts.tv_usec = (t % 1_000_000) as _;
            writer.write(&nh, d)?;
        }
        passes += 1;
    }
    let capped = (passes as i64) * shift < target_us;
    Ok((passes, Some(last as f64 / 1_000_000.0), truncated, capped))
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

#[derive(Debug, Clone)]
pub struct WindowSelection {
    pub start_abs: f64,
    pub end_abs: f64,
    pub start_rel: f64,
    pub window_packets: u64,
    pub rule: String,
}

#[derive(Debug, Clone)]
pub struct CaptureDensityProfile {
    pub lo: f64,
    pub hi: f64,
    pub total_packets: u64,
    pub bin_size: f64,
    pub bins: Vec<u32>,
}

/// Profile packet density across time: single header pass binning packet arrival rate.
fn profile_capture_density(path: &Path) -> Result<Option<CaptureDensityProfile>, Box<dyn Error>> {
    let mut cap = Capture::from_file(path)?;
    let mut lo: Option<f64> = None;
    let mut hi: Option<f64> = None;
    let mut total_packets = 0u64;
    let mut bin_size = 1.0f64;
    let mut bins: Vec<u32> = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        let t = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        // Ignore uninitialized or invalid epoch timestamps
        if t < 0.0 || t > 2_500_000_000.0 {
            continue;
        }
        total_packets += 1;
        let t_lo = *lo.get_or_insert(t);
        let cur_hi = hi.get_or_insert(t);
        if t < t_lo {
            lo = Some(t);
        }
        if t > *cur_hi {
            *cur_hi = t;
        }

        let mut offset = t - t_lo;
        if offset < 0.0 {
            offset = 0.0;
        }
        let mut idx = (offset / bin_size) as usize;

        // Cap bin count at 500,000 to bound memory (< 2 MB) even for multi-day captures
        while idx >= 500_000 {
            let mut new_bins = Vec::with_capacity((bins.len() + 1) / 2);
            for chunk in bins.chunks(2) {
                new_bins.push(chunk.iter().sum());
            }
            bins = new_bins;
            bin_size *= 2.0;
            idx = (offset / bin_size) as usize;
        }

        if idx >= bins.len() {
            bins.resize(idx + 1, 0);
        }
        bins[idx] = bins[idx].saturating_add(1);
    }

    match (lo, hi) {
        (Some(lo), Some(hi)) => Ok(Some(CaptureDensityProfile {
            lo,
            hi,
            total_packets,
            bin_size,
            bins,
        })),
        _ => Ok(None),
    }
}

/// Widen a selected window symmetrically (bin by bin, clamped to the capture) until it holds
/// at least `min_packets` packets or covers the whole capture.
fn widen_window(
    profile: &CaptureDensityProfile,
    sel: WindowSelection,
    min_packets: u64,
    max_span: f64,
    window_s: f64,
    flow_starts: Option<&[f64]>,
) -> WindowSelection {
    if min_packets == 0 || sel.window_packets >= min_packets || profile.bins.is_empty() {
        return sel;
    }
    let n = profile.bins.len();
    let mut i0 = (((sel.start_abs - profile.lo) / profile.bin_size)
        .floor()
        .max(0.0) as usize)
        .min(n);
    let mut i1 = (((sel.end_abs - profile.lo) / profile.bin_size)
        .ceil()
        .max(0.0) as usize)
        .clamp(i0, n);
    let count = |a: usize, b: usize| -> u64 { profile.bins[a..b].iter().map(|&c| c as u64).sum() };
    let mut total = count(i0, i1);
    // Widening is bounded: a step that would take the window past `max_span` is not taken.
    let mut capped = false;
    while total < min_packets && (i0 > 0 || i1 < n) {
        let ni0 = i0.saturating_sub(1);
        let ni1 = (i1 + 1).min(n);
        if ((ni1 - ni0) as f64) * profile.bin_size > max_span {
            capped = true;
            break;
        }
        i0 = ni0;
        i1 = ni1;
        total = count(i0, i1);
    }
    if capped && total < min_packets {
        return densest_loop_window(profile, window_s, flow_starts).unwrap_or(sel);
    }
    if i0 == 0 && i1 == n {
        return WindowSelection {
            start_abs: profile.lo,
            end_abs: profile.lo + (n as f64) * profile.bin_size,
            start_rel: 0.0,
            window_packets: total,
            rule: "whole_capture".to_string(),
        };
    }
    let start_rel = (i0 as f64) * profile.bin_size;
    WindowSelection {
        start_abs: profile.lo + start_rel,
        end_abs: profile.lo + (i1 as f64) * profile.bin_size,
        start_rel,
        window_packets: total,
        rule: "widened".to_string(),
    }
}

/// Densest `window_s` window that holds at least one flow start (when flow starts are known;
/// otherwise any window); the capture's first flow start anchors it when no window qualifies.
/// Loop-fill repeats it to fill the window. Rule `densest_loop`.
fn densest_loop_window(
    profile: &CaptureDensityProfile,
    window_s: f64,
    flow_starts: Option<&[f64]>,
) -> Option<WindowSelection> {
    let b_count = ((window_s / profile.bin_size).round() as usize).max(1);
    if profile.bins.len() <= b_count {
        return None;
    }
    let num = profile.bins.len() - b_count + 1;
    let mut sum: u64 = profile.bins[..b_count].iter().map(|&c| c as u64).sum();
    let mut best: Option<(usize, u64)> = None;
    for i in 0..num {
        if i > 0 {
            sum = sum - (profile.bins[i - 1] as u64) + (profile.bins[i + b_count - 1] as u64);
        }
        let ws = profile.lo + (i as f64) * profile.bin_size;
        let ok = match flow_starts {
            Some(starts) if !starts.is_empty() => {
                let k = starts.partition_point(|&t| t < ws);
                k < starts.len() && starts[k] < ws + window_s
            }
            _ => true,
        };
        if ok && best.is_none_or(|(_, b)| sum > b) {
            best = Some((i, sum));
        }
    }
    let (start_abs, start_rel, packets) = match best {
        Some((i, c)) => {
            let rel = (i as f64) * profile.bin_size;
            (profile.lo + rel, rel, c)
        }
        None => {
            let first = flow_starts.and_then(|s| s.first().copied())?;
            let i0 = (((first - profile.lo) / profile.bin_size).floor().max(0.0) as usize)
                .min(profile.bins.len());
            let i1 = (i0 + b_count).min(profile.bins.len());
            let c: u64 = profile.bins[i0..i1].iter().map(|&c| c as u64).sum();
            (first, first - profile.lo, c)
        }
    };
    Some(WindowSelection {
        start_abs,
        end_abs: start_abs + window_s,
        start_rel,
        window_packets: packets,
        rule: "densest_loop".to_string(),
    })
}

/// Density-aware window selection: never selects an empty window.
/// Picks among windows holding >= min_density_ratio * median packet rate (or densest),
/// inside a labelled attack span when provided.
fn select_density_aware_window(
    profile: &CaptureDensityProfile,
    window_s: f64,
    seed: Option<u64>,
    attack_span: Option<(f64, f64)>,
    min_density_ratio: f64,
    flow_starts: Option<&[f64]>,
) -> Option<WindowSelection> {
    if window_s <= 0.0 || profile.total_packets == 0 {
        return None;
    }
    let duration = profile.hi - profile.lo;
    if duration <= window_s {
        return Some(WindowSelection {
            start_abs: profile.lo,
            end_abs: profile.lo + window_s,
            start_rel: 0.0,
            window_packets: profile.total_packets,
            rule: "whole_capture".to_string(),
        });
    }

    let b_count = ((window_s / profile.bin_size).round() as usize).max(1);
    if profile.bins.len() <= b_count {
        return Some(WindowSelection {
            start_abs: profile.lo,
            end_abs: profile.lo + window_s,
            start_rel: 0.0,
            window_packets: profile.total_packets,
            rule: "whole_capture".to_string(),
        });
    }

    let num_candidates = profile.bins.len() - b_count + 1;
    let mut candidate_counts: Vec<u64> = Vec::with_capacity(num_candidates);
    let mut cur_sum: u64 = profile.bins[..b_count].iter().map(|&c| c as u64).sum();
    candidate_counts.push(cur_sum);
    for i in 1..num_candidates {
        cur_sum = cur_sum - (profile.bins[i - 1] as u64) + (profile.bins[i + b_count - 1] as u64);
        candidate_counts.push(cur_sum);
    }

    // Flow-start anchoring: only windows that contain at least one flow start are candidates.
    // With fewer than two such windows there is no density choice to make, so the window is
    // anchored at the capture's first flow start.
    let allowed: Vec<bool> = match flow_starts {
        Some(starts) if !starts.is_empty() => (0..num_candidates)
            .map(|i| {
                let ws = profile.lo + (i as f64) * profile.bin_size;
                let we = ws + window_s;
                let k = starts.partition_point(|&t| t < ws);
                k < starts.len() && starts[k] < we
            })
            .collect(),
        _ => vec![true; num_candidates],
    };
    if let Some(starts) = flow_starts
        && !starts.is_empty()
        && allowed.iter().filter(|&&a| a).count() <= 1
    {
        let first = starts[0];
        let i0 = (((first - profile.lo) / profile.bin_size).floor().max(0.0) as usize)
            .min(profile.bins.len());
        let i1 = (i0 + b_count).min(profile.bins.len());
        let window_packets: u64 = profile.bins[i0..i1].iter().map(|&c| c as u64).sum();
        return Some(WindowSelection {
            start_abs: first,
            end_abs: first + window_s,
            start_rel: first - profile.lo,
            window_packets,
            rule: "first_flow_start".to_string(),
        });
    }
    let anchored = flow_starts.is_some_and(|s| !s.is_empty());

    let max_count = (0..num_candidates)
        .filter(|&i| allowed[i])
        .map(|i| candidate_counts[i])
        .max()
        .unwrap_or(0);
    if max_count == 0 {
        return Some(WindowSelection {
            start_abs: profile.lo,
            end_abs: profile.lo + window_s,
            start_rel: 0.0,
            window_packets: 0,
            rule: "zero_packets".to_string(),
        });
    }

    let mut non_zero_counts: Vec<u64> = candidate_counts
        .iter()
        .copied()
        .filter(|&c| c > 0)
        .collect();
    non_zero_counts.sort_unstable();
    let median_count = if non_zero_counts.is_empty() {
        1u64
    } else {
        non_zero_counts[non_zero_counts.len() / 2]
    };

    let threshold = ((median_count as f64) * min_density_ratio).max(1.0).floor() as u64;

    let is_in_attack_span = |idx: usize| -> bool {
        if let Some((att_lo, att_hi)) = attack_span {
            let win_start = profile.lo + (idx as f64) * profile.bin_size;
            let win_end = win_start + window_s;
            win_start < att_hi && win_end > att_lo
        } else {
            true
        }
    };

    let mut eligible: Vec<usize> = (0..num_candidates)
        .filter(|&i| allowed[i] && candidate_counts[i] >= threshold && is_in_attack_span(i))
        .collect();
    let mut rule = if attack_span.is_some() {
        "density_aware_attack_span".to_string()
    } else {
        "density_aware".to_string()
    };

    if eligible.is_empty() && attack_span.is_some() {
        let in_span: Vec<usize> = (0..num_candidates)
            .filter(|&i| allowed[i] && is_in_attack_span(i) && candidate_counts[i] > 0)
            .collect();
        if !in_span.is_empty() {
            let max_span = in_span.iter().map(|&i| candidate_counts[i]).max().unwrap();
            eligible = in_span
                .into_iter()
                .filter(|&i| candidate_counts[i] == max_span)
                .collect();
            rule = "densest_attack_span".to_string();
        }
    }

    if eligible.is_empty() {
        eligible = (0..num_candidates)
            .filter(|&i| allowed[i] && candidate_counts[i] >= threshold)
            .collect();
        rule = "density_aware".to_string();
    }

    if eligible.is_empty() {
        eligible = (0..num_candidates)
            .filter(|&i| allowed[i] && candidate_counts[i] == max_count)
            .collect();
        rule = "densest_fallback".to_string();
    }
    if anchored {
        rule = match rule.as_str() {
            "density_aware" => "flow_start_density".to_string(),
            "density_aware_attack_span" => "flow_start_density_attack_span".to_string(),
            _ => rule,
        };
    }

    let selected_idx = match seed {
        None => eligible[0],
        Some(s) => {
            let digest =
                md5::compute(format!("density_window|{}|{}", s, eligible.len()).as_bytes());
            let val = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize;
            eligible[val % eligible.len()]
        }
    };

    let start_rel = (selected_idx as f64) * profile.bin_size;
    let start_abs = profile.lo + start_rel;
    let end_abs = start_abs + window_s;
    let window_packets = candidate_counts[selected_idx];

    Some(WindowSelection {
        start_abs,
        end_abs,
        start_rel,
        window_packets,
        rule,
    })
}

/// First ephemeral port that the variation seed shifts (IANA dynamic range
/// starts at 49152; 32768 covers the Linux default range too).
const EPHEMERAL_PORT_FLOOR: u16 = 32768;

/// Seed-derived ephemeral-port offset in 1..32768.
fn ephemeral_port_offset(seed: u64) -> u16 {
    let digest = md5::compute(format!("ports|{}", seed).as_bytes());
    let v = u16::from_be_bytes([digest[0], digest[1]]) % (u16::MAX - EPHEMERAL_PORT_FLOOR);
    v + 1
}

/// Shift TCP/UDP ports >= 32768 by `offset`, wrapping within [32768, 65535].
/// A function of the port value alone, so both directions of a flow stay
/// consistent. Returns true when a port changed.
fn shift_ephemeral_ports(
    transport: &mut [u8],
    protocol: IpNextHeaderProtocol,
    offset: u16,
) -> bool {
    if offset == 0
        || !matches!(
            protocol,
            IpNextHeaderProtocols::Tcp | IpNextHeaderProtocols::Udp
        )
        || transport.len() < 4
    {
        return false;
    }
    let span = u32::from(u16::MAX - EPHEMERAL_PORT_FLOOR) + 1; // 32768
    let mut changed = false;
    for off in [0usize, 2] {
        let port = u16::from_be_bytes([transport[off], transport[off + 1]]);
        if port >= EPHEMERAL_PORT_FLOOR {
            let rel = (u32::from(port - EPHEMERAL_PORT_FLOOR) + u32::from(offset)) % span;
            let moved = EPHEMERAL_PORT_FLOOR + rel as u16;
            transport[off..off + 2].copy_from_slice(&moved.to_be_bytes());
            changed |= moved != port;
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
    /// Variation seed: salts every address hash.
    seed: Option<u64>,
    /// Ephemeral-port shift under `seed` (0 when unseeded).
    port_offset: u16,
}

impl AddressRewriter {
    fn new(topology_path: Option<&Path>) -> Self {
        Self::with_seed(topology_path, None)
    }

    fn with_seed(topology_path: Option<&Path>, seed: Option<u64>) -> Self {
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

        let port_offset = seed.map(ephemeral_port_offset).unwrap_or(0);
        Self {
            edge_ips,
            group_a,
            group_b,
            mapping_v4: HashMap::new(),
            mapping_v6: HashMap::new(),
            seed,
            port_offset,
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
            if shift_ephemeral_ports(ipv4_packet.payload_mut(), protocol, self.port_offset) {
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
        let ip_string = match self.seed {
            Some(seed) => format!("{}|{}", seed, ip),
            None => ip.to_string(),
        };
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

        let seed = Self::ipv6_seed(ip, self.seed);
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

    fn ipv6_seed(ip: Ipv6Addr, salt: Option<u64>) -> u32 {
        let mut octets: Vec<u8> = Vec::with_capacity(24);
        if let Some(seed) = salt {
            octets.extend_from_slice(&seed.to_be_bytes());
        }
        octets.extend_from_slice(&ip.octets());
        let md5_digest = md5::compute(&octets);
        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&octets);
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
            shift_ephemeral_ports(&mut out[34..], next_header, rewriter.port_offset);
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

/// Removes the timestamp-sorted temporary capture when dropped.
struct SortedTemp(PathBuf);

impl Drop for SortedTemp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn record_micros(h: &pcap::PacketHeader) -> i64 {
    h.ts.tv_sec as i64 * 1_000_000 + h.ts.tv_usec as i64
}

/// Count records that are earlier than their predecessor. When there are any, write the
/// capture to `tmp` in timestamp order (stable: ties keep file order) and return the count.
fn sort_capture_by_time(
    input: &Path,
    linktype: Linktype,
    tmp: &Path,
) -> Result<u64, Box<dyn Error>> {
    let mut cap = Capture::from_file(input)?;
    let mut records: Vec<(pcap::PacketHeader, Vec<u8>)> = Vec::new();
    let mut out_of_order = 0_u64;
    let mut prev: Option<i64> = None;
    while let Ok(p) = cap.next_packet() {
        let t = record_micros(p.header);
        if prev.is_some_and(|q| t < q) {
            out_of_order += 1;
        }
        prev = Some(t);
        records.push((*p.header, p.data.to_vec()));
    }
    if out_of_order == 0 {
        return Ok(0);
    }
    records.sort_by_key(|(h, _)| record_micros(h));
    let mut writer = PcapWriter::create(tmp, linktype)?;
    for (h, d) in &records {
        writer.write(h, d)?;
    }
    writer.finish()?;
    Ok(out_of_order)
}

fn perform_rewrite(config: &RewriteConfig) -> Result<RewriteOutcome, Box<dyn Error>> {
    if !config.input.exists() {
        return Err(format!("Input capture not found: {}", config.input.display()).into());
    }

    let input_format = detect_capture_format(&config.input)?;
    let input_size = fs::metadata(&config.input)?.len();
    let mut capture = Capture::from_file(&config.input)?;
    let input_linktype = capture.get_datalink();
    let mut address_rewriter = AddressRewriter::with_seed(config.topology.as_deref(), config.seed);

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
                seed: config.seed,
                ephemeral_port_offset: config.seed.map(|_| address_rewriter.port_offset),
                window_anchor: None,
                flows_kept: 0,
                flows_dropped_partial: 0,
                packets_dropped_partial: 0,
                input_unsorted: false,
                input_out_of_order_packets: 0,
                window_seconds: None,
                window_start_seconds: None,
                source_duration_seconds: None,
                packets_outside_window: 0,
                window_packets: None,
                window_rule: None,
                loop_passes: 1,
                max_loop_passes: config.max_loop_passes,
                loop_capped: false,
                loop_truncated_packets: 0,
                output_span_seconds: None,
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

    // Windowing reads timestamps in order: an unsorted capture is sorted into a temporary
    // file next to the output, and every later read uses that file.
    let mut input_out_of_order_packets = 0_u64;
    let mut sorted_guard: Option<SortedTemp> = None;
    if config.window_seconds.is_some() {
        let mut tmp_name = config.output.as_os_str().to_owned();
        tmp_name.push(".sorted.tmp");
        let tmp = PathBuf::from(tmp_name);
        let n = sort_capture_by_time(&config.input, input_linktype, &tmp);
        let guard = SortedTemp(tmp);
        input_out_of_order_packets = n?;
        if input_out_of_order_packets > 0 {
            capture = Capture::from_file(&guard.0)?;
            sorted_guard = Some(guard);
        }
    }
    let input_unsorted = input_out_of_order_packets > 0;
    let src_path: PathBuf = sorted_guard
        .as_ref()
        .map(|g| g.0.clone())
        .unwrap_or_else(|| config.input.clone());

    let profile = match config.window_seconds {
        Some(_) => profile_capture_density(&src_path)?,
        None => None,
    };
    let flow_first = if config.window_seconds.is_some()
        && profile.is_some()
        && config.window_anchor == WindowAnchor::FlowStart
    {
        Some(flow_first_seen(&src_path)?)
    } else {
        None
    };
    let mut flow_starts: Vec<f64> = flow_first
        .as_ref()
        .map(|m| m.values().copied().collect())
        .unwrap_or_default();
    flow_starts.sort_by(|a, b| a.total_cmp(b));
    let window_sel = config.window_seconds.and_then(|w| {
        profile.as_ref().and_then(|p| {
            let attack_span = config.attack_start.zip(config.attack_end).map(|(s, e)| {
                let a_lo = if s < p.lo { p.lo + s } else { s };
                let a_hi = if e < p.lo { p.lo + e } else { e };
                (a_lo, a_hi)
            });
            let starts = if flow_starts.is_empty() {
                None
            } else {
                Some(flow_starts.as_slice())
            };
            select_density_aware_window(
                p,
                w,
                config.seed,
                attack_span,
                config.min_density_ratio,
                starts,
            )
            .map(|sel| {
                let max_span = config.max_window_span.unwrap_or(2.0 * w);
                widen_window(p, sel, config.min_window_packets, max_span, w, starts)
            })
        })
    });
    let mut kept_flows: HashSet<FlowKey> = HashSet::new();
    let mut dropped_flows: HashSet<FlowKey> = HashSet::new();
    let mut packets_dropped_partial = 0_u64;
    let loop_enabled = config.loop_fill && window_sel.is_some();
    let target_span = config.window_seconds.unwrap_or(0.0);
    // Processed records of the first pass, kept only while the pass is still shorter than
    // the requested window (dropped as soon as no looping can be needed).
    let mut loop_buf: Vec<(pcap::PacketHeader, Vec<u8>)> = Vec::new();
    let mut loop_buffering = loop_enabled;
    let mut loop_passes = 1_u64;
    let mut loop_capped = false;
    let mut loop_truncated_packets = 0_u64;
    let mut last_out_timestamp: Option<f64> = None;
    let mut first_out_timestamp: Option<f64> = None;
    let mut packets_outside_window = 0_u64;

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
                if let Some(ref sel) = window_sel {
                    let key = flow_first
                        .as_ref()
                        .and_then(|_| flow_key(input_linktype, packet.data));
                    match (key, flow_first.as_ref()) {
                        (Some(k), Some(first)) => {
                            if timestamp < sel.start_abs
                                || timestamp >= sel.end_abs + config.flow_grace_seconds
                            {
                                packets_outside_window += 1;
                                continue;
                            }
                            let f = first.get(&k).copied().unwrap_or(timestamp);
                            if f < sel.start_abs || f >= sel.end_abs {
                                packets_dropped_partial += 1;
                                dropped_flows.insert(k);
                                continue;
                            }
                            kept_flows.insert(k);
                        }
                        _ => {
                            if timestamp < sel.start_abs || timestamp >= sel.end_abs {
                                packets_outside_window += 1;
                                continue;
                            }
                        }
                    }
                }
                first_timestamp.get_or_insert(timestamp);
                last_timestamp = Some(timestamp);
                // Min/max, not first/last record: input timestamps may be unsorted.
                last_out_timestamp =
                    Some(last_out_timestamp.map_or(timestamp, |l| l.max(timestamp)));
                first_out_timestamp =
                    Some(first_out_timestamp.map_or(timestamp, |f| f.min(timestamp)));
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
                if loop_buffering {
                    if timestamp - first_timestamp.unwrap_or(timestamp) >= target_span {
                        loop_buffering = false;
                        loop_buf = Vec::new();
                    } else {
                        loop_buf.push((header, data.clone()));
                    }
                }

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

    if flow_first.as_ref().is_some_and(|m| !m.is_empty()) && last_out_timestamp.is_none() {
        return Err(format!(
            "flow-start anchored window kept no packets although the input has {} IP flows",
            flow_first.as_ref().map_or(0, |m| m.len())
        )
        .into());
    }

    if loop_buffering && !loop_buf.is_empty() {
        let (passes, last_ts, truncated, capped) =
            emit_loop_passes(&mut writer, &loop_buf, target_span, config.max_loop_passes)?;
        loop_passes = passes;
        loop_capped = capped;
        loop_truncated_packets = truncated;
        if let Some(t) = last_ts {
            last_out_timestamp = Some(last_out_timestamp.map_or(t, |l| l.max(t)));
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
            seed: config.seed,
            ephemeral_port_offset: config.seed.map(|_| address_rewriter.port_offset),
            window_seconds: config.window_seconds,
            window_start_seconds: window_sel
                .as_ref()
                .map(|s| s.start_rel)
                .or(config.window_seconds.map(|_| 0.0)),
            source_duration_seconds: profile.as_ref().map(|p| p.hi - p.lo),
            packets_outside_window,
            window_packets: window_sel.as_ref().map(|s| s.window_packets),
            window_rule: window_sel.as_ref().map(|s| s.rule.clone()),
            loop_passes,
            max_loop_passes: config.max_loop_passes,
            loop_capped,
            loop_truncated_packets,
            output_span_seconds: first_out_timestamp
                .zip(last_out_timestamp)
                .map(|(first, last)| (last - first).max(0.0)),
            window_anchor: window_sel
                .as_ref()
                .map(|_| config.window_anchor.name().to_string()),
            flows_kept: kept_flows.len() as u64,
            flows_dropped_partial: dropped_flows.len() as u64,
            packets_dropped_partial,
            input_unsorted,
            input_out_of_order_packets,
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
            seed: None,
            window_seconds: None,
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill: false,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
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
            seed: None,
            window_seconds: None,
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill: false,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
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
            seed: None,
            window_seconds: None,
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill: false,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
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
            seed: None,
            window_seconds: None,
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill: false,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
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

    fn mapping_for(seed: Option<u64>, dir: &std::path::Path) -> Vec<Ipv4Addr> {
        let mut rw = AddressRewriter::with_seed(Some(&topology_with_collectors(dir)), seed);
        (0..64u32)
            .map(|i| rw.map_ipv4_with_preference(Ipv4Addr::from(0xC633_6400u32 + i * 7), None))
            .collect()
    }

    /// Step 2 of the variation plan (2026-10-30): the same capture lands on
    /// different hosts per episode seed, reproducibly; no seed keeps the
    /// unsalted mapping every earlier run used.
    #[test]
    fn a_seed_salts_the_mapping_reproducibly_and_none_keeps_the_old_one() {
        let tmp = tempdir().unwrap();
        let a1 = mapping_for(Some(1), tmp.path());
        let a2 = mapping_for(Some(1), tmp.path());
        let b = mapping_for(Some(2), tmp.path());
        let none = mapping_for(None, tmp.path());
        assert_eq!(a1, a2, "same seed, same mapping");
        assert_ne!(a1, b, "different seeds move addresses");
        // Unseeded: md5 of the address text, as before the seed existed.
        let rw = AddressRewriter::new(Some(&topology_with_collectors(tmp.path())));
        for (i, mapped) in none.iter().enumerate() {
            let ip = Ipv4Addr::from(0xC633_6400u32 + i as u32 * 7);
            let d = md5::compute(ip.to_string().as_bytes());
            let idx = (u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as usize) % rw.edge_ips.len();
            assert_eq!(*mapped, rw.edge_ips[idx]);
        }
        for seed in 0..50u64 {
            for m in mapping_for(Some(seed), tmp.path()) {
                assert!(
                    m.octets()[2] == 1 || m.octets()[2] == 5,
                    "seed {} mapped onto {}",
                    seed,
                    m
                );
            }
        }
    }

    #[test]
    fn ephemeral_ports_shift_consistently_and_service_ports_stay() {
        for seed in [1u64, 7, 99, 12345] {
            let off = ephemeral_port_offset(seed);
            assert!((1..32768).contains(&off));
            let mut fwd = [0u8; 8];
            fwd[0..2].copy_from_slice(&50000u16.to_be_bytes());
            fwd[2..4].copy_from_slice(&443u16.to_be_bytes());
            let mut rev = [0u8; 8];
            rev[0..2].copy_from_slice(&443u16.to_be_bytes());
            rev[2..4].copy_from_slice(&50000u16.to_be_bytes());
            assert!(shift_ephemeral_ports(
                &mut fwd,
                IpNextHeaderProtocols::Tcp,
                off
            ));
            assert!(shift_ephemeral_ports(
                &mut rev,
                IpNextHeaderProtocols::Tcp,
                off
            ));
            let fwd_src = u16::from_be_bytes([fwd[0], fwd[1]]);
            assert_eq!(
                fwd_src,
                u16::from_be_bytes([rev[2], rev[3]]),
                "both directions agree"
            );
            assert!(fwd_src >= EPHEMERAL_PORT_FLOOR && fwd_src != 50000);
            assert_eq!(
                u16::from_be_bytes([fwd[2], fwd[3]]),
                443,
                "service port kept"
            );
        }
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&65535u16.to_be_bytes());
        shift_ephemeral_ports(&mut udp, IpNextHeaderProtocols::Udp, 1);
        assert_eq!(
            u16::from_be_bytes([udp[0], udp[1]]),
            EPHEMERAL_PORT_FLOOR,
            "wraps inside the range"
        );
        let mut icmp = [0u8; 8];
        assert!(!shift_ephemeral_ports(
            &mut icmp,
            IpNextHeaderProtocols::Icmp,
            5
        ));
    }

    #[test]
    fn the_manifest_records_the_seed_and_port_offset() -> Result<(), Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("input.pcap");
        fs::write(&input, minimal_pcap_with_packet()?)?;
        let manifest = tmp.path().join("manifest.json");
        let cli = RewriteCli {
            input,
            output: Some(tmp.path().join("out.pcap")),
            manifest: Some(manifest.clone()),
            topology: Some(topology_with_collectors(tmp.path())),
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
            seed: Some(42),
            window_seconds: None,
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill: false,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
        };
        run(cli)?;
        let m: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        assert_eq!(m["stats"]["seed"], 42);
        assert_eq!(
            m["stats"]["ephemeral_port_offset"],
            u64::from(ephemeral_port_offset(42))
        );
        Ok(())
    }

    /// A classic pcap with one UDP packet per second for `seconds` seconds.
    fn timed_pcap(seconds: u32) -> Result<Vec<u8>, Box<dyn Error>> {
        let one = minimal_pcap_with_packet()?;
        let frame = &one[24 + 16..];
        let mut bytes = minimal_pcap_header();
        for t in 0..seconds {
            bytes.extend_from_slice(&(1_000 + t).to_le_bytes()); // ts sec
            bytes.extend_from_slice(&0u32.to_le_bytes()); // ts usec
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(frame);
        }
        Ok(bytes)
    }

    fn windowed(
        seconds: u32,
        window: f64,
        seed: Option<u64>,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("in.pcap");
        fs::write(&input, timed_pcap(seconds)?)?;
        let manifest = tmp.path().join("m.json");
        run(RewriteCli {
            input,
            output: Some(tmp.path().join("out.pcap")),
            manifest: Some(manifest.clone()),
            topology: Some(topology_with_collectors(tmp.path())),
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
            seed,
            window_seconds: Some(window),
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill: false,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
        })?;
        let mut m: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        let mut cap = Capture::from_file(tmp.path().join("out.pcap"))?;
        let mut kept = 0u64;
        let mut first = None;
        while let Ok(p) = cap.next_packet() {
            kept += 1;
            first.get_or_insert(p.header.ts.tv_sec as u64);
        }
        m["kept"] = kept.into();
        m["first_sec"] = first.unwrap_or(0).into();
        Ok(m)
    }

    /// Native-speed windows (2026-10-30): every capture replays at real speed,
    /// so a long one contributes a seeded S-second window instead of being
    /// squeezed into S seconds (the squeeze ratio identified the dataset).
    #[test]
    fn a_long_capture_keeps_a_seeded_window_at_its_own_timing() -> Result<(), Box<dyn Error>> {
        let a = windowed(100, 10.0, Some(3))?;
        let b = windowed(100, 10.0, Some(4))?;
        let none = windowed(100, 10.0, None)?;
        assert_eq!(a["kept"], 10);
        assert_eq!(a["stats"]["packets_outside_window"], 90);
        assert_eq!(a["stats"]["source_duration_seconds"], 99.0);
        let start = a["stats"]["window_start_seconds"].as_f64().unwrap();
        assert!((0.0..=89.0).contains(&start));
        assert_eq!(
            a["first_sec"].as_u64().unwrap(),
            1_000 + start.ceil() as u64,
            "timing is the capture's own"
        );
        assert_ne!(
            a["stats"]["window_start_seconds"], b["stats"]["window_start_seconds"],
            "the seed moves the window"
        );
        assert_eq!(none["stats"]["window_start_seconds"], 0.0);
        assert_eq!(none["first_sec"], 1_000);
        Ok(())
    }

    #[test]
    fn a_capture_shorter_than_the_window_is_kept_whole() -> Result<(), Box<dyn Error>> {
        let m = windowed(5, 10.0, Some(3))?;
        assert_eq!(m["kept"], 5);
        assert_eq!(m["stats"]["packets_outside_window"], 0);
        assert_eq!(m["stats"]["window_start_seconds"], 0.0);
        assert_eq!(m["stats"]["window_packets"], 5);
        assert_eq!(m["stats"]["window_rule"], "whole_capture");
        Ok(())
    }

    #[test]
    fn density_aware_window_never_picks_empty_windows() -> Result<(), Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("deadzone.pcap");
        // Create a pcap with 50s deadzone (0 packets) followed by 20 packets from t=1050 to t=1069
        let one = minimal_pcap_with_packet()?;
        let frame = &one[24 + 16..];
        let mut bytes = minimal_pcap_header();
        for t in 50u32..70u32 {
            bytes.extend_from_slice(&(1_000u32 + t).to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(frame);
        }
        fs::write(&input, bytes)?;
        let manifest = tmp.path().join("m.json");
        run(RewriteCli {
            input,
            output: Some(tmp.path().join("out.pcap")),
            manifest: Some(manifest.clone()),
            topology: Some(topology_with_collectors(tmp.path())),
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
            seed: Some(12345),
            window_seconds: Some(10.0),
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill: false,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
        })?;
        let m: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        let kept = m["stats"]["window_packets"].as_u64().unwrap();
        assert!(kept > 0, "density-aware window must never select 0 packets");
        let rule = m["stats"]["window_rule"].as_str().unwrap();
        assert!(rule.contains("density_aware") || rule.contains("densest"));
        Ok(())
    }

    #[test]
    fn density_aware_respects_attack_span() -> Result<(), Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("attack_span.pcap");
        // Packets from t=1000 to t=1100 (1 pkt/sec)
        fs::write(&input, timed_pcap(100)?)?;
        let manifest = tmp.path().join("m.json");
        run(RewriteCli {
            input,
            output: Some(tmp.path().join("out.pcap")),
            manifest: Some(manifest.clone()),
            topology: Some(topology_with_collectors(tmp.path())),
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
            seed: Some(999),
            window_seconds: Some(10.0),
            attack_start: Some(1040.0),
            attack_end: Some(1060.0),
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill: false,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
        })?;
        let m: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        let start = m["stats"]["window_start_seconds"].as_f64().unwrap();
        // Capture start is 1000. Window start relative to 1000 should overlap [40, 60]
        assert!(
            start + 10.0 > 40.0 && start < 60.0,
            "window must overlap attack span"
        );
        assert_eq!(m["stats"]["window_rule"], "density_aware_attack_span");
        Ok(())
    }
    /// Capture with packets at the given (sec, usec) timestamps.
    fn pcap_at(times: &[(u32, u32)]) -> Result<Vec<u8>, Box<dyn Error>> {
        let one = minimal_pcap_with_packet()?;
        let frame = &one[24 + 16..];
        let mut bytes = minimal_pcap_header();
        for (s, us) in times {
            bytes.extend_from_slice(&s.to_le_bytes());
            bytes.extend_from_slice(&us.to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(frame);
        }
        Ok(bytes)
    }

    /// Rewrite `times` with a window; returns (manifest, output timestamps in microseconds).
    fn windowed_at(
        times: &[(u32, u32)],
        window: f64,
        min_packets: u64,
        loop_fill: bool,
    ) -> Result<(serde_json::Value, Vec<i64>), Box<dyn Error>> {
        windowed_capped(times, window, min_packets, loop_fill, 1000)
    }

    fn windowed_capped(
        times: &[(u32, u32)],
        window: f64,
        min_packets: u64,
        loop_fill: bool,
        max_loop_passes: u64,
    ) -> Result<(serde_json::Value, Vec<i64>), Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("in.pcap");
        fs::write(&input, pcap_at(times)?)?;
        let manifest = tmp.path().join("m.json");
        run(RewriteCli {
            input,
            output: Some(tmp.path().join("out.pcap")),
            manifest: Some(manifest.clone()),
            topology: Some(topology_with_collectors(tmp.path())),
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
            seed: None,
            window_seconds: Some(window),
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: min_packets,
            loop_fill,
            max_loop_passes,
            window_anchor: WindowAnchor::Time,
            flow_grace_seconds: 5.0,
            max_window_span: None,
        })?;
        let m: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        let mut cap = Capture::from_file(tmp.path().join("out.pcap"))?;
        let mut ts = Vec::new();
        while let Ok(p) = cap.next_packet() {
            ts.push(p.header.ts.tv_sec as i64 * 1_000_000 + p.header.ts.tv_usec as i64);
        }
        Ok((m, ts))
    }

    #[test]
    fn a_tiny_capture_is_looped_to_fill_the_window() -> Result<(), Box<dyn Error>> {
        let times = [(1_000, 0), (1_000, 50_000), (1_000, 100_000)];
        let (m, ts) = windowed_at(&times, 30.0, 0, true)?;
        let passes = m["stats"]["loop_passes"].as_u64().unwrap();
        assert!(passes > 1, "passes {passes}");
        assert_eq!(ts.len() as u64, 3 * passes);
        let span = m["stats"]["output_span_seconds"].as_f64().unwrap();
        // T034: the final pass is cut at W, so the span is below W (passes at 0, 10, 20 s).
        assert!(span < 30.0 && span >= 20.0, "span {span}");
        assert!((ts[ts.len() - 1] - ts[0]) as f64 / 1e6 < 30.0);
        for pass in ts.chunks(3) {
            assert_eq!(pass[1] - pass[0], 50_000, "within-pass gap kept");
            assert_eq!(pass[2] - pass[1], 50_000, "within-pass gap kept");
        }
        // pass shift = max(pass span 0.1 s + median gap 0.05 s, min shift W / packets = 10 s)
        assert_eq!(ts[3] - ts[0], 10_000_000);
        let (off, ts_off) = windowed_at(&times, 30.0, 0, false)?;
        assert_eq!(off["stats"]["loop_passes"], 1);
        assert_eq!(ts_off.len(), 3);
        Ok(())
    }

    #[test]
    fn the_loop_pass_cap_stops_the_loop_before_the_window() -> Result<(), Box<dyn Error>> {
        // 20 packets 1 ms apart: pass shift = max(0.02 s, 30 s / 20 = 1.5 s) -> 20 passes fill 30 s
        let times: Vec<(u32, u32)> = (0..20).map(|i| (1_000, i * 1_000)).collect();
        let (m, ts) = windowed_capped(&times, 30.0, 0, true, 3)?;
        assert_eq!(m["stats"]["loop_passes"], 3);
        assert_eq!(m["stats"]["max_loop_passes"], 3);
        assert_eq!(m["stats"]["loop_capped"], true);
        assert_eq!(ts.len(), 60);
        let span = m["stats"]["output_span_seconds"].as_f64().unwrap();
        assert!(span < 30.0, "span {span}");
        // default cap: the window stops the loop (same passes as the uncapped code), not the cap
        let (d, _) = windowed_at(&times, 30.0, 0, true)?;
        assert_eq!(d["stats"]["max_loop_passes"], 1000);
        assert_eq!(d["stats"]["loop_capped"], false);
        assert_eq!(d["stats"]["loop_passes"], 20);
        Ok(())
    }

    #[test]
    fn a_sparse_density_window_is_widened_to_the_minimum_packets() -> Result<(), Box<dyn Error>> {
        // one packet per second for 100 s; a 10 s window holds 10, the minimum is 15 (T034: was 25,
        // which now exceeds the 2 * W widening bound).
        let times: Vec<(u32, u32)> = (0..100).map(|t| (1_000 + t, 0)).collect();
        let (m, ts) = windowed_at(&times, 10.0, 15, true)?;
        assert_eq!(m["stats"]["window_rule"], "widened");
        let wp = m["stats"]["window_packets"].as_u64().unwrap();
        assert!(wp >= 15, "window packets {wp}");
        assert_eq!(ts.len() as u64, wp);
        assert_eq!(m["stats"]["loop_passes"], 1);
        // T034: a minimum that bounded widening (2 * W = 20 s) cannot reach falls back to the
        // densest W window, looped, instead of widening to the whole capture.
        let (m2, _) = windowed_at(&times, 10.0, 500, true)?;
        assert_eq!(m2["stats"]["window_rule"], "densest_loop");
        assert!(m2["stats"]["window_packets"].as_u64().unwrap() <= 11);
        Ok(())
    }

    #[test]
    fn a_dense_capture_window_is_unchanged() -> Result<(), Box<dyn Error>> {
        // 10 packets per second for 100 s; a 10 s window holds 100 packets.
        let times: Vec<(u32, u32)> = (0..1000)
            .map(|i| (1_000 + i / 10, (i % 10) * 100_000))
            .collect();
        let (m, ts) = windowed_at(&times, 10.0, 50, true)?;
        assert_eq!(m["stats"]["loop_passes"], 1);
        assert_eq!(m["stats"]["window_packets"], 100);
        assert_ne!(m["stats"]["window_rule"], "widened");
        assert_eq!(ts.len(), 100);
        Ok(())
    }

    /// Capture with packets (sec, usec, source port); every packet is the minimal UDP frame with
    /// its source port patched, so each distinct port is its own flow.
    fn pcap_flows(pkts: &[(u32, u32, u16)]) -> Result<Vec<u8>, Box<dyn Error>> {
        let one = minimal_pcap_with_packet()?;
        let frame = &one[24 + 16..];
        let mut bytes = minimal_pcap_header();
        for (s, us, sport) in pkts {
            let mut f = frame.to_vec();
            f[34..36].copy_from_slice(&sport.to_be_bytes());
            bytes.extend_from_slice(&s.to_le_bytes());
            bytes.extend_from_slice(&us.to_le_bytes());
            bytes.extend_from_slice(&(f.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(f.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&f);
        }
        Ok(bytes)
    }

    fn run_flows(
        pkts: &[(u32, u32, u16)],
        window: f64,
        attack: Option<(f64, f64)>,
        anchor: WindowAnchor,
        loop_fill: bool,
    ) -> Result<(serde_json::Value, Vec<i64>), Box<dyn Error>> {
        let tmp = tempdir()?;
        let input = tmp.path().join("in.pcap");
        fs::write(&input, pcap_flows(pkts)?)?;
        let manifest = tmp.path().join("m.json");
        run(RewriteCli {
            input,
            output: Some(tmp.path().join("out.pcap")),
            manifest: Some(manifest.clone()),
            topology: Some(topology_with_collectors(tmp.path())),
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
            seed: None,
            window_seconds: Some(window),
            attack_start: attack.map(|a| a.0),
            attack_end: attack.map(|a| a.1),
            min_density_ratio: 0.10,
            min_window_packets: 0,
            loop_fill,
            max_loop_passes: 1000,
            window_anchor: anchor,
            flow_grace_seconds: 5.0,
            max_window_span: None,
        })?;
        let m: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        let mut cap = Capture::from_file(tmp.path().join("out.pcap"))?;
        let mut ts = Vec::new();
        while let Ok(p) = cap.next_packet() {
            ts.push(p.header.ts.tv_sec as i64 * 1_000_000 + p.header.ts.tv_usec as i64);
        }
        Ok((m, ts))
    }

    /// A long flow (port 1111, one packet per second from t=0 to 99) begins before the window;
    /// a short flow (port 2222, 3 packets) begins inside every window the attack span allows.
    fn long_and_short() -> Vec<(u32, u32, u16)> {
        let mut v: Vec<(u32, u32, u16)> = (0..100).map(|t| (1_000 + t, 0, 1111)).collect();
        v.extend([
            (1_060, 200_000, 2222),
            (1_060, 400_000, 2222),
            (1_061, 0, 2222),
        ]);
        v.sort();
        v
    }

    #[test]
    fn flow_start_anchor_keeps_only_flows_that_begin_inside_the_window()
    -> Result<(), Box<dyn Error>> {
        let pkts = long_and_short();
        let (m, ts) = run_flows(
            &pkts,
            10.0,
            Some((60.0, 60.5)),
            WindowAnchor::FlowStart,
            false,
        )?;
        assert_eq!(m["stats"]["window_anchor"], "flow_start");
        assert_eq!(m["stats"]["flows_kept"], 1);
        assert_eq!(m["stats"]["flows_dropped_partial"], 1);
        assert!(m["stats"]["packets_dropped_partial"].as_u64().unwrap() > 0);
        // only the short flow's three packets survive
        assert_eq!(ts.len(), 3, "kept {ts:?}");
        // time anchoring keeps the long flow's packets too
        let (mt, tt) = run_flows(&pkts, 10.0, Some((60.0, 60.5)), WindowAnchor::Time, false)?;
        assert_eq!(mt["stats"]["window_anchor"], "time");
        assert!(tt.len() > 3);
        assert_eq!(mt["stats"]["flows_dropped_partial"], 0);
        Ok(())
    }

    #[test]
    fn one_long_flow_starting_at_t0_anchors_at_its_start_and_is_not_empty()
    -> Result<(), Box<dyn Error>> {
        let pkts: Vec<(u32, u32, u16)> = (0..100).map(|t| (1_000 + t, 0, 1111)).collect();
        let (m, ts) = run_flows(&pkts, 10.0, None, WindowAnchor::FlowStart, false)?;
        assert_eq!(m["stats"]["window_rule"], "first_flow_start");
        assert_eq!(m["stats"]["window_start_seconds"], 0.0);
        assert!(!ts.is_empty(), "output empty");
        assert!(ts.len() >= 10, "kept {ts:?}");
        Ok(())
    }

    #[test]
    fn the_densest_region_of_continuing_flows_is_skipped_for_a_window_with_a_flow_start()
    -> Result<(), Box<dyn Error>> {
        // Flow 1111 starts at t=0 and is sparse, then dense in 60..70; flows 2222 and 3333 start
        // at t=20 and t=30 with one packet each. The densest window (60..70) holds no start.
        let mut pkts: Vec<(u32, u32, u16)> = (0..100).map(|t| (1_000 + t, 0, 1111)).collect();
        for t in 60..70 {
            for k in 1..10 {
                pkts.push((1_000 + t, k * 100_000, 1111));
            }
        }
        pkts.push((1_020, 500_000, 2222));
        pkts.push((1_030, 500_000, 3333));
        pkts.sort();
        let (m, ts) = run_flows(&pkts, 10.0, None, WindowAnchor::FlowStart, false)?;
        let start = m["stats"]["window_start_seconds"].as_f64().unwrap();
        assert!(
            (start <= 20.5 && 20.5 < start + 10.0)
                || (start <= 30.5 && 30.5 < start + 10.0)
                || start == 0.0,
            "window start {start} holds no flow start"
        );
        assert!(!ts.is_empty(), "output empty");
        assert!(m["stats"]["flows_kept"].as_u64().unwrap() >= 1);
        Ok(())
    }

    #[test]
    fn an_unsorted_pass_loops_to_fill_the_window_without_hitting_the_cap()
    -> Result<(), Box<dyn Error>> {
        // Last record earlier than the first (shuffled capture): file-order span is
        // negative; the loop must use the min..max extent (T032).
        let mut pkts = vec![(1_029, 0, 1111)];
        pkts.extend(std::iter::repeat_n((1_000, 0, 1111), 1_099));
        let (m, _ts) = run_flows(&pkts, 30.0, None, WindowAnchor::FlowStart, true)?;
        let passes = m["stats"]["loop_passes"].as_u64().unwrap();
        assert!(passes > 1 && passes < 1000, "passes {passes}");
        let span = m["stats"]["output_span_seconds"].as_f64().unwrap();
        assert!((29.0..30.0).contains(&span), "span {span}"); // T034: final pass truncated at W
        Ok(())
    }

    #[test]
    fn a_zero_span_capture_loops_with_increasing_pass_starts() -> Result<(), Box<dyn Error>> {
        let pkts = [(1_000, 0, 1111), (1_000, 0, 1111), (1_000, 0, 1111)];
        let (m, ts) = run_flows(&pkts, 30.0, None, WindowAnchor::FlowStart, true)?;
        let passes = m["stats"]["loop_passes"].as_u64().unwrap();
        assert!(passes > 1, "passes {passes}");
        let starts: Vec<i64> = ts.chunks(3).map(|c| c[0]).collect();
        assert!(starts.windows(2).all(|w| w[1] > w[0]), "starts {starts:?}");
        let span = m["stats"]["output_span_seconds"].as_f64().unwrap();
        assert!((20.0..30.0).contains(&span), "span {span}"); // T034: passes at 0, 10, 20 s
        Ok(())
    }

    #[test]
    fn an_unsorted_capture_is_windowed_on_its_sorted_form() -> Result<(), Box<dyn Error>> {
        // 60 records over 20 s in order, then reversed in file order: the sorted form
        // fits a 30 s window, the file order does not.
        let mut times: Vec<(u32, u32)> = (0..60)
            .map(|i| (1_000 + i / 3, (i % 3) * 100_000))
            .collect();
        times.reverse();
        let (m, _ts) = windowed_at(&times, 30.0, 1, true)?;
        assert_eq!(m["stats"]["input_unsorted"], true);
        assert!(m["stats"]["input_out_of_order_packets"].as_u64().unwrap() > 0);
        let span = m["stats"]["output_span_seconds"].as_f64().unwrap();
        // W + flow grace + one loop shift (one pass extent, ~20 s here).
        assert!(span <= 30.0 + 5.0 + 20.5, "span {span}");
        assert!(m["stats"]["loop_passes"].as_u64().unwrap() < 10);
        Ok(())
    }

    #[test]
    fn a_sorted_capture_is_not_resorted_and_keeps_its_order() -> Result<(), Box<dyn Error>> {
        let times: Vec<(u32, u32)> = (0..20).map(|i| (1_000 + i, 0)).collect();
        let (m, ts) = windowed_at(&times, 60.0, 1, false)?;
        assert_eq!(m["stats"]["input_unsorted"], false);
        assert_eq!(m["stats"]["input_out_of_order_packets"], 0);
        let want: Vec<i64> = times
            .iter()
            .map(|(s, u)| *s as i64 * 1_000_000 + *u as i64)
            .collect();
        assert_eq!(ts, want);
        Ok(())
    }

    /// Like `windowed_at` with flow-start anchoring, looping on, and one flow per packet.
    fn windowed_at_flows(
        times: &[(u32, u32)],
        window: f64,
        min_packets: u64,
    ) -> Result<(serde_json::Value, Vec<i64>), Box<dyn Error>> {
        let pkts: Vec<(u32, u32, u16)> = times
            .iter()
            .enumerate()
            .map(|(i, (s, u))| (*s, *u, 1_000 + i as u16))
            .collect();
        let tmp = tempdir()?;
        let input = tmp.path().join("in.pcap");
        fs::write(&input, pcap_flows(&pkts)?)?;
        let manifest = tmp.path().join("m.json");
        run(RewriteCli {
            input,
            output: Some(tmp.path().join("out.pcap")),
            manifest: Some(manifest.clone()),
            topology: Some(topology_with_collectors(tmp.path())),
            verbose: 0,
            dry_run: false,
            progress_every: 0,
            max_packets: None,
            seed: None,
            window_seconds: Some(window),
            attack_start: None,
            attack_end: None,
            min_density_ratio: 0.10,
            min_window_packets: min_packets,
            loop_fill: true,
            max_loop_passes: 1000,
            window_anchor: WindowAnchor::FlowStart,
            flow_grace_seconds: 5.0,
            max_window_span: None,
        })?;
        let m: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        let mut cap = Capture::from_file(tmp.path().join("out.pcap"))?;
        let mut ts = Vec::new();
        while let Ok(p) = cap.next_packet() {
            ts.push(p.header.ts.tv_sec as i64 * 1_000_000 + p.header.ts.tv_usec as i64);
        }
        Ok((m, ts))
    }

    #[test]
    fn a_sparse_capture_never_widens_past_twice_the_window() -> Result<(), Box<dyn Error>> {
        // 150 packets spread over 3000 s (one every 20 s); W = 30, minimum 200.
        let times: Vec<(u32, u32)> = (0..150).map(|i| (1_000 + i * 20, 0)).collect();
        let (m, ts) = windowed_at_flows(&times, 30.0, 200)?;
        let span = m["stats"]["output_span_seconds"].as_f64().unwrap();
        assert!(span <= 30.0 + 5.0, "span {span}");
        let rule = m["stats"]["window_rule"].as_str().unwrap();
        assert!(rule == "densest_loop" || rule == "widened", "rule {rule}");
        assert!(!ts.is_empty());
        Ok(())
    }

    #[test]
    fn the_final_loop_pass_is_truncated_at_the_window() -> Result<(), Box<dyn Error>> {
        // A 20 s pass (one packet per second, 21 packets) with W = 30: pass 2 starts at 21 s
        // (extent 20 s + median gap 1 s) and is cut at 30 s.
        let times: Vec<(u32, u32)> = (0..21).map(|i| (1_000 + i, 0)).collect();
        let (m, ts) = windowed_at(&times, 30.0, 0, true)?;
        assert_eq!(m["stats"]["loop_passes"], 2);
        let cut = m["stats"]["loop_truncated_packets"].as_u64().unwrap();
        assert!(cut > 0, "truncated {cut}");
        assert_eq!(ts.len() as u64 + cut, 42);
        let span = m["stats"]["output_span_seconds"].as_f64().unwrap();
        assert!(span < 30.0 && span <= 30.0 + 5.0, "span {span}");
        assert!((ts[ts.len() - 1] - ts[0]) < 30_000_000);
        Ok(())
    }
}
