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
use pnet::packet::tcp::{MutableTcpPacket, ipv4_checksum as tcp_ipv4_checksum};
use pnet::packet::udp::{MutableUdpPacket, ipv4_checksum as udp_ipv4_checksum};
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

#[derive(Debug, Serialize, Clone, Default)]
struct RewriteStats {
    packets_total: u64,
    packets_converted: u64,
    packets_remapped: u64,
    packets_ipv6_converted: u64,
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

fn default_output_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("pcap");
    let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("pcap");
    parent.join(format!("{}_rewritten.{}", stem, ext))
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
                let name = node.get("name").and_then(|n| n.as_str()).unwrap_or("");
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

        if changed {
            ipv4_packet.set_checksum(0);
            let checksum = ipv4_checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);

            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    if let Some(mut udp_packet) = MutableUdpPacket::new(ipv4_packet.payload_mut()) {
                        udp_packet.set_checksum(0);
                        let checksum =
                            udp_ipv4_checksum(&udp_packet.to_immutable(), &mapped_src, &mapped_dst);
                        udp_packet.set_checksum(checksum);
                    }
                }
                IpNextHeaderProtocols::Tcp => {
                    if let Some(mut tcp_packet) = MutableTcpPacket::new(ipv4_packet.payload_mut()) {
                        tcp_packet.set_checksum(0);
                        let checksum =
                            tcp_ipv4_checksum(&tcp_packet.to_immutable(), &mapped_src, &mapped_dst);
                        tcp_packet.set_checksum(checksum);
                    }
                }
                _ => {}
            }

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

fn rewrite_ipv6_packet(
    rewriter: &mut AddressRewriter,
    ethernet: &EthernetPacket,
) -> Result<Vec<u8>, String> {
    let ipv6_packet =
        Ipv6Packet::new(ethernet.payload()).ok_or_else(|| "Malformed IPv6 payload".to_string())?;

    let src_v6 = ipv6_packet.get_source();
    let dst_v6 = ipv6_packet.get_destination();

    let mapped_src = rewriter.map_ipv6_with_preference(src_v6, None);
    let mapped_dst = rewriter.map_ipv6_with_preference(dst_v6, Some(mapped_src));

    let next_header = ipv6_packet.get_next_header();
    let hop_limit = ipv6_packet.get_hop_limit();
    let mut payload = ipv6_packet.payload().to_vec();

    match next_header {
        IpNextHeaderProtocols::Udp => {
            if let Some(mut udp_packet) = MutableUdpPacket::new(&mut payload) {
                udp_packet.set_checksum(0);
                let checksum =
                    udp_ipv4_checksum(&udp_packet.to_immutable(), &mapped_src, &mapped_dst);
                udp_packet.set_checksum(checksum);
            } else {
                return Err("Malformed UDP payload".to_string());
            }
        }
        IpNextHeaderProtocols::Tcp => {
            if let Some(mut tcp_packet) = MutableTcpPacket::new(&mut payload) {
                tcp_packet.set_checksum(0);
                let checksum =
                    tcp_ipv4_checksum(&tcp_packet.to_immutable(), &mapped_src, &mapped_dst);
                tcp_packet.set_checksum(checksum);
            } else {
                return Err("Malformed TCP payload".to_string());
            }
        }
        IpNextHeaderProtocols::Icmpv6 => {
            if payload.len() >= 4 {
                payload[0] = match payload[0] {
                    128 => 8,
                    129 => 0,
                    other => other,
                };
                payload[2] = 0;
                payload[3] = 0;
                if let Some(mut icmp_packet) =
                    pnet::packet::icmp::MutableIcmpPacket::new(&mut payload)
                {
                    icmp_packet.set_checksum(0);
                    let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
                    icmp_packet.set_checksum(checksum);
                }
            }
        }
        _ => {}
    }

    let total_length = (20 + payload.len()) as u16;
    let mut ipv4_bytes = vec![0u8; 20];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_bytes)
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

    let mut frame = vec![0u8; 14 + ipv4_bytes.len() + payload.len()];
    {
        let mut ethernet_packet =
            MutableEthernetPacket::new(&mut frame).ok_or_else(|| "Frame alloc".to_string())?;
        ethernet_packet.set_destination(ethernet.get_destination());
        ethernet_packet.set_source(ethernet.get_source());
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        let ipv4_payload = ethernet_packet.payload_mut();
        ipv4_payload[..20].copy_from_slice(&ipv4_bytes);
        ipv4_payload[20..].copy_from_slice(&payload);
    }

    Ok(frame)
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
        let start = Instant::now();
        while capture.next_packet().is_ok() {
            packets_total += 1;

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

    let dead = Capture::dead(output_linktype)?;
    let output_path = config
        .output
        .to_str()
        .ok_or("Output path must be valid UTF-8")?;
    let mut writer = dead.savefile(output_path)?;

    let mut packets_total = 0_u64;
    let mut packets_converted = 0_u64;
    let mut packets_remapped = 0_u64;
    let mut packets_ipv6_converted = 0_u64;
    let mut warnings = Vec::new();
    let start = Instant::now();

    loop {
        match capture.next_packet() {
            Ok(packet) => {
                packets_total += 1;
                let mut data = packet.data.to_vec();
                let mut header = *packet.header;

                if input_linktype == Linktype(113) {
                    match convert_sll_to_ethernet(&data) {
                        Ok(converted) => {
                            if converted.len() != data.len() {
                                packets_converted += 1;
                            }
                            header.caplen = converted.len() as u32;
                            header.len = converted.len() as u32;
                            data = converted;
                        }
                        Err(e) => {
                            warnings.push(format!(
                                "SLL conversion failed for packet {}: {} (writing original frame)",
                                packets_total, e
                            ));
                        }
                    }
                }

                if let Some(ethernet_view) = EthernetPacket::new(&data)
                    && ethernet_view.get_ethertype() == EtherTypes::Ipv6
                {
                    match rewrite_ipv6_packet(&mut address_rewriter, &ethernet_view) {
                        Ok(converted) => {
                            packets_ipv6_converted += 1;
                            header.caplen = converted.len() as u32;
                            header.len = converted.len() as u32;
                            data = converted;
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

                let packet_for_write = pcap::Packet::new(&header, &data);
                writer.write(&packet_for_write);

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

    writer.flush()?;

    let mut outcome = RewriteOutcome {
        stats: RewriteStats {
            packets_total,
            packets_converted,
            packets_remapped,
            packets_ipv6_converted,
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

fn convert_sll_to_ethernet(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 16 {
        return Err("SLL frame too short".to_string());
    }

    let mut proto = u16::from_be_bytes([data[14], data[15]]);
    if proto == 0 {
        proto = 0x0800; // default to IPv4 when SLL header omits ethertype
    }
    let payload = &data[16..];

    let (src_mac, dst_mac) = derive_macs(payload);

    let mut ethernet = Vec::with_capacity(14 + payload.len());
    ethernet.extend_from_slice(&dst_mac);
    ethernet.extend_from_slice(&src_mac);
    ethernet.extend_from_slice(&proto.to_be_bytes());
    ethernet.extend_from_slice(payload);
    Ok(ethernet)
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
}
