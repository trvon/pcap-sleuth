// Import statements at the top
use chrono::{DateTime, TimeZone, Utc};
use clap::{ArgAction, Parser};
use csv::ReaderBuilder;
use env_logger::Env;
use ipnetwork::IpNetwork;
use log::{debug, info, warn};
use pcap::Capture;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File, create_dir_all};
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

#[derive(Parser, Debug)]
#[command(
    name = "pcap-sleuth",
    version,
    author,
    about = "A tool to process PCAP files and extract network flow data"
)]
struct Cli {
    /// Input PCAP file
    #[arg(short, long, value_name = "PCAP")]
    input: PathBuf,

    /// Output directory
    #[arg(short, long, value_name = "DIR")]
    output_dir: PathBuf,

    /// Enable CSV output
    #[arg(short = 'c', long)]
    csv: bool,

    /// Enable JSON output
    #[arg(short = 'j', long)]
    json: bool,

    /// Verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Label rules CSV file
    #[arg(short = 'l', long, value_name = "LABELS")]
    labels: Option<PathBuf>,

    /// Enable heuristic-based attack detection
    #[arg(long)]
    detect_attacks: bool,

    /// Maximum distinct ports for port scan detection (default: 20)
    #[arg(long, default_value = "20")]
    scan_threshold: usize,

    /// Maximum distinct ports for UDP scan detection (default: 15)
    #[arg(long, default_value = "15")]
    udp_scan_threshold: usize,

    /// Configuration file path
    #[arg(long, value_name = "CONFIG")]
    config: Option<PathBuf>,

    /// Path to Suricata EVE JSON alerts file
    #[arg(long, value_name = "EVE_JSON")]
    suricata_alerts: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketInfo {
    pub timestamp: DateTime<Utc>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<u8>,
    pub length: u32,
    pub payload_length: usize,
    pub tcp_flags: Option<u8>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub flow_id: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub ip_a: IpAddr,
    pub ip_b: IpAddr,
    pub port_a: u16,
    pub port_b: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Option<Self> {
        if protocol == 6 || protocol == 17 {
            match src_ip.cmp(&dst_ip) {
                Ordering::Less => Some(FlowKey {
                    ip_a: src_ip,
                    ip_b: dst_ip,
                    port_a: src_port,
                    port_b: dst_port,
                    protocol,
                }),
                Ordering::Greater => Some(FlowKey {
                    ip_a: dst_ip,
                    ip_b: src_ip,
                    port_a: dst_port,
                    port_b: src_port,
                    protocol,
                }),
                Ordering::Equal => {
                    if src_port <= dst_port {
                        Some(FlowKey {
                            ip_a: src_ip,
                            ip_b: dst_ip,
                            port_a: src_port,
                            port_b: dst_port,
                            protocol,
                        })
                    } else {
                        Some(FlowKey {
                            ip_a: dst_ip,
                            ip_b: src_ip,
                            port_a: dst_port,
                            port_b: src_port,
                            protocol,
                        })
                    }
                }
            }
        } else {
            None
        }
    }
    pub fn to_string_id(&self) -> String {
        format!(
            "{}-{}:{}-{}:{}",
            self.protocol, self.ip_a, self.port_a, self.ip_b, self.port_b
        )
    }
}

#[derive(Debug, Clone)]
pub struct FlowData {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub packets: Vec<PacketInfo>,
    pub label: Option<String>,
    pub attack_type: Option<String>,
    pub suricata_alerts: Vec<SuricataAlert>,
}

impl Default for FlowData {
    fn default() -> Self {
        Self {
            start_time: Utc::now(),
            end_time: Utc::now(),
            last_seen: Utc::now(),
            packet_count: 0,
            byte_count: 0,
            packets: Vec::new(),
            label: None,
            attack_type: None,
            suricata_alerts: Vec::new(),
        }
    }
}

/// Summary data for JSON output
#[derive(Serialize)]
struct FlowSummary {
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    packet_count: u64,
    byte_count: u64,
    label: Option<String>,
    protocol: u8,
    ip_a: IpAddr,
    port_a: u16,
    ip_b: IpAddr,
    port_b: u16,
    attack_type: Option<String>,
}

/// Write per-packet CSV
fn write_packet_csv(packets: &[PacketInfo], output_path: &Path) -> Result<(), Box<dyn Error>> {
    let file = File::create(output_path)?;
    let mut wtr = csv::Writer::from_writer(file);
    wtr.write_record([
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "length",
        "payload_length",
        "tcp_flags",
        "icmp_type",
        "icmp_code",
        "flow_id",
        "label",
    ])?;
    for pkt in packets {
        wtr.write_record([
            &pkt.timestamp.to_rfc3339(),
            &pkt.src_ip.map_or("".to_string(), |ip| ip.to_string()),
            &pkt.dst_ip.map_or("".to_string(), |ip| ip.to_string()),
            &pkt.src_port.map_or("".to_string(), |port| port.to_string()),
            &pkt.dst_port.map_or("".to_string(), |port| port.to_string()),
            &pkt.protocol.map_or("".to_string(), |p| p.to_string()),
            &pkt.length.to_string(),
            &pkt.payload_length.to_string(),
            &pkt.tcp_flags.map_or("".to_string(), |f| f.to_string()),
            &pkt.icmp_type.map_or("".to_string(), |t| t.to_string()),
            &pkt.icmp_code.map_or("".to_string(), |c| c.to_string()),
            &pkt.flow_id.clone().unwrap_or_default(),
            &pkt.label.clone().unwrap_or_default(),
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

/// Write flow-based JSON keyed by flow ID
fn write_flow_json(
    flows: &HashMap<FlowKey, FlowData>,
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut map = serde_json::Map::new();
    for (key, data) in flows {
        let id = key.to_string_id();
        let summary = FlowSummary {
            start_time: data.start_time,
            end_time: data.end_time,
            packet_count: data.packet_count,
            byte_count: data.byte_count,
            label: data.label.clone(),
            protocol: key.protocol,
            ip_a: key.ip_a,
            port_a: key.port_a,
            ip_b: key.ip_b,
            port_b: key.port_b,
            attack_type: data.attack_type.clone(),
        };
        map.insert(id, serde_json::to_value(summary)?);
    }
    let file = File::create(output_path)?;
    serde_json::to_writer_pretty(file, &map)?;
    Ok(())
}

/// Track source IP statistics for attack detection
#[derive(Debug, Clone, Default)]
struct SourceStats {
    /// Total number of packets sent from this source
    packet_count: u64,
    /// Destination IPs contacted
    dst_ips: HashSet<IpAddr>,
    /// Destination ports contacted per IP
    dst_ports: HashMap<IpAddr, HashSet<u16>>,
    /// Destination IPs contacted per port (for port sweep detection)
    dst_ips_per_port: HashMap<u16, HashSet<IpAddr>>,
    /// TCP SYN packets sent per destination IP
    syn_packets: HashMap<IpAddr, u32>,
    /// Timestamps of SYN packets sent to specific destination services
    syn_timestamps: HashMap<(IpAddr, u16), Vec<DateTime<Utc>>>,
    /// ICMP Echo Request (ping) packets sent per destination IP
    ping_packets: HashMap<IpAddr, u32>,
    /// Successful TCP connections per destination IP and port
    successful_connections: HashMap<IpAddr, HashSet<u16>>,
}

/// Possible attack types detected by heuristics
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum AttackType {
    TcpSynScan,
    TcpConnectScan,
    UdpScan,
    SynFlood,
    PortSweep,
    PingSweep,
    SuricataAlert,
}

impl AttackType {
    fn to_string(&self) -> String {
        match self {
            AttackType::TcpSynScan => "TCP SYN Scan".to_string(),
            AttackType::TcpConnectScan => "TCP Connect Scan".to_string(),
            AttackType::UdpScan => "UDP Scan".to_string(),
            AttackType::SynFlood => "SYN Flood".to_string(),
            AttackType::PortSweep => "Port Sweep".to_string(),
            AttackType::PingSweep => "Ping Sweep".to_string(),
            AttackType::SuricataAlert => "Suricata Alert".to_string(),
        }
    }
}

/// Configuration file structure
#[derive(Deserialize, Debug, Default)]
struct Config {
    #[serde(default)]
    detection: DetectionConfig,
    #[serde(default)]
    flow: FlowConfig,
    #[serde(default)]
    suricata: SuricataConfig,
    // Add other configuration sections later if needed
}

#[derive(Deserialize, Debug, Default)]
struct DetectionConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    heuristics: HeuristicConfig,
    #[serde(default)]
    labels: LabelConfig,
}

#[derive(Deserialize, Debug)]
struct HeuristicConfig {
    #[serde(default)]
    syn_scan: ScanConfig,
    #[serde(default)]
    connect_scan: ScanConfig,
    #[serde(default)]
    udp_scan: ScanConfig,
    #[serde(default)]
    syn_flood: SynFloodConfig,
    #[serde(default)]
    port_sweep: PortSweepConfig,
    #[serde(default)]
    ping_sweep: ScanConfig,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            syn_scan: ScanConfig {
                enabled: default_true(),
                threshold: default_scan_threshold(),
            },
            connect_scan: ScanConfig {
                enabled: default_true(),
                threshold: default_scan_threshold(),
            },
            udp_scan: ScanConfig {
                enabled: default_true(),
                threshold: default_udp_scan_threshold(),
            },
            syn_flood: SynFloodConfig::default(),
            port_sweep: PortSweepConfig::default(),
            ping_sweep: ScanConfig {
                enabled: default_true(),
                threshold: default_ping_sweep_threshold(),
            },
        }
    }
}

#[derive(Deserialize, Debug)]
struct ScanConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_scan_threshold")]
    threshold: usize,
}

#[derive(Deserialize, Debug, Default)]
struct SynFloodConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_syn_flood_threshold")]
    rate_threshold: u32,
    #[serde(default = "default_syn_flood_window")]
    time_window_secs: u64,
}

#[derive(Deserialize, Debug, Default)]
struct PortSweepConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_port_sweep_threshold")]
    threshold: usize,
}

#[derive(Deserialize, Debug)]
struct LabelConfig {
    #[serde(default = "default_attack_label_format")]
    attack_format: String,
}

#[derive(Deserialize, Debug, Default)]
struct FlowConfig {
    #[serde(default = "default_tcp_timeout")]
    tcp_timeout_secs: u64,
    #[serde(default = "default_udp_timeout")]
    udp_timeout_secs: u64,
    #[serde(default = "default_check_interval")]
    check_interval: u64,
}

#[derive(Deserialize, Debug, Default)]
struct SuricataConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_suricata_alert_format")]
    alert_format: String,
}

fn default_suricata_alert_format() -> String {
    "suricata:{alert_category}:{signature}".to_string()
}

// Default value helper functions
fn default_true() -> bool {
    true
}
fn default_scan_threshold() -> usize {
    20
}
fn default_udp_scan_threshold() -> usize {
    15
} // Lower threshold for UDP scans
fn default_attack_label_format() -> String {
    "attack:{type}".to_string()
}
fn default_tcp_timeout() -> u64 {
    300
} // 5 minutes
fn default_udp_timeout() -> u64 {
    180
} // 3 minutes
fn default_check_interval() -> u64 {
    1000
} // Check every 1000 packets
fn default_syn_flood_threshold() -> u32 {
    100
} // 100 SYNs per second
fn default_syn_flood_window() -> u64 {
    1
} // 1 second time window
fn default_port_sweep_threshold() -> usize {
    10
} // 10 distinct destination IPs
fn default_ping_sweep_threshold() -> usize {
    5
} // 5 distinct destination IPs for ping sweep

// Default trait implementations for optional structs
impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            threshold: default_scan_threshold(),
        }
    }
}

impl Default for LabelConfig {
    fn default() -> Self {
        Self {
            attack_format: default_attack_label_format(),
        }
    }
}

//
// The parse_packet function is inspired by:
// - https://github.com/75-keyboard/rust_learn
// - https://github.com/8mamo10/mrhc-rust
// This implementation is adapted and modified for use in pcap-sleuth
//
fn parse_packet(data: &[u8], ts: DateTime<Utc>, length: u32) -> PacketInfo {
    let mut pkt = PacketInfo {
        timestamp: ts,
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        protocol: None,
        length,
        payload_length: 0,
        tcp_flags: None,
        icmp_type: None,
        icmp_code: None,
        flow_id: None,
        label: None,
    };
    if let Some(eth_pkt) = EthernetPacket::new(data) {
        match eth_pkt.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ip_pkt) = Ipv4Packet::new(eth_pkt.payload()) {
                    pkt.src_ip = Some(IpAddr::V4(ip_pkt.get_source()));
                    pkt.dst_ip = Some(IpAddr::V4(ip_pkt.get_destination()));
                    let proto = ip_pkt.get_next_level_protocol();
                    pkt.protocol = Some(proto.0);
                    if proto == IpNextHeaderProtocols::Tcp {
                        if let Some(tcp_pkt) = TcpPacket::new(ip_pkt.payload()) {
                            pkt.src_port = Some(tcp_pkt.get_source());
                            pkt.dst_port = Some(tcp_pkt.get_destination());
                            pkt.tcp_flags = Some(tcp_pkt.get_flags());
                            pkt.payload_length = tcp_pkt.payload().len();
                        } else {
                            warn!("Failed to parse TCP packet");
                        }
                    } else if proto == IpNextHeaderProtocols::Udp {
                        if let Some(udp_pkt) = UdpPacket::new(ip_pkt.payload()) {
                            pkt.src_port = Some(udp_pkt.get_source());
                            pkt.dst_port = Some(udp_pkt.get_destination());
                            pkt.payload_length = udp_pkt.payload().len();
                        } else {
                            warn!("Failed to parse UDP packet");
                        }
                    } else if proto == IpNextHeaderProtocols::Icmp {
                        if let Some(icmp_pkt) = IcmpPacket::new(ip_pkt.payload()) {
                            pkt.protocol = Some(1); // ICMP
                            pkt.icmp_type = Some(icmp_pkt.get_icmp_type().0);
                            pkt.icmp_code = Some(icmp_pkt.get_icmp_code().0);
                            pkt.payload_length = icmp_pkt.payload().len();
                        } else {
                            warn!("Failed to parse ICMP packet");
                        }
                    }
                } else {
                    warn!("Failed to parse IPv4 packet");
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ip6_pkt) = Ipv6Packet::new(eth_pkt.payload()) {
                    pkt.src_ip = Some(IpAddr::V6(ip6_pkt.get_source()));
                    pkt.dst_ip = Some(IpAddr::V6(ip6_pkt.get_destination()));
                    let proto = ip6_pkt.get_next_header();
                    pkt.protocol = Some(proto.0);
                    if proto == IpNextHeaderProtocols::Tcp {
                        if let Some(tcp_pkt) = TcpPacket::new(ip6_pkt.payload()) {
                            pkt.src_port = Some(tcp_pkt.get_source());
                            pkt.dst_port = Some(tcp_pkt.get_destination());
                            pkt.tcp_flags = Some(tcp_pkt.get_flags());
                            pkt.payload_length = tcp_pkt.payload().len();
                        } else {
                            warn!("Failed to parse TCPv6 packet");
                        }
                    } else if proto == IpNextHeaderProtocols::Udp {
                        if let Some(udp_pkt) = UdpPacket::new(ip6_pkt.payload()) {
                            pkt.src_port = Some(udp_pkt.get_source());
                            pkt.dst_port = Some(udp_pkt.get_destination());
                            pkt.payload_length = udp_pkt.payload().len();
                        } else {
                            warn!("Failed to parse UDPv6 packet");
                        }
                    } else if proto == IpNextHeaderProtocols::Icmpv6 {
                        if let Some(icmpv6_pkt) = Icmpv6Packet::new(ip6_pkt.payload()) {
                            pkt.protocol = Some(58); // ICMPv6
                            pkt.icmp_type = Some(icmpv6_pkt.get_icmpv6_type().0);
                            pkt.icmp_code = Some(icmpv6_pkt.get_icmpv6_code().0);
                            pkt.payload_length = icmpv6_pkt.payload().len();
                        } else {
                            warn!("Failed to parse ICMPv6 packet");
                        }
                    }
                } else {
                    warn!("Failed to parse IPv6 packet");
                }
            }
            _ => {
                debug!("Unsupported EtherType: {:?}", eth_pkt.get_ethertype());
            }
        }
    } else {
        warn!("Failed to parse Ethernet packet");
    }
    pkt
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // Load configuration file if provided
    let config = if let Some(config_path) = &cli.config {
        info!("Loading configuration from {:?}", config_path);
        match fs::read_to_string(config_path) {
            Ok(content) => match toml::from_str::<Config>(&content) {
                Ok(config) => {
                    info!("Configuration loaded successfully");
                    config
                }
                Err(e) => {
                    warn!("Failed to parse configuration file: {}", e);
                    Config::default()
                }
            },
            Err(e) => {
                warn!("Failed to read configuration file: {}", e);
                Config::default()
            }
        }
    } else {
        Config::default()
    };

    // Setup logging level based on verbosity
    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).init();

    info!("Starting pcap-sleuth v{}", env!("CARGO_PKG_VERSION"));
    info!("Input file: {:?}", cli.input);
    info!("Output directory: {:?}", cli.output_dir);
    info!("CSV output: {}", cli.csv);
    info!("JSON output: {}", cli.json);

    // Determine if attack detection is enabled (CLI flag overrides config)
    let detect_attacks = cli.detect_attacks || config.detection.enabled;
    if detect_attacks {
        info!("Attack detection enabled");

        // Use CLI thresholds if provided, otherwise use config values
        let tcp_scan_threshold = cli.scan_threshold;
        let udp_scan_threshold = cli.udp_scan_threshold;

        info!("TCP scan threshold: {}", tcp_scan_threshold);
        info!("UDP scan threshold: {}", udp_scan_threshold);

        // Log which heuristics are enabled from config
        info!(
            "SYN scan detection: {}",
            config.detection.heuristics.syn_scan.enabled
        );
        info!(
            "Connect scan detection: {}",
            config.detection.heuristics.connect_scan.enabled
        );
        info!(
            "UDP scan detection: {}",
            config.detection.heuristics.udp_scan.enabled
        );
        info!(
            "SYN flood detection: {}",
            config.detection.heuristics.syn_flood.enabled
        );
        info!(
            "Port sweep detection: {}",
            config.detection.heuristics.port_sweep.enabled
        );
        info!(
            "Ping sweep detection: {}",
            config.detection.heuristics.ping_sweep.enabled
        );
    }

    // Load label rules if provided
    let mut label_rules: Vec<LabelRule> = Vec::new();
    if let Some(label_path) = &cli.labels {
        label_rules = parse_label_rules(label_path)?;
        info!("Loaded {} label rules", label_rules.len());
    }

    create_dir_all(&cli.output_dir)?;

    let mut cap = Capture::from_file(&cli.input)
        .map_err(|e| format!("Failed to open pcap file {:?}: {}", cli.input, e))?;
    let mut count = 0;
    let mut all_packets: Vec<PacketInfo> = Vec::new();
    while let Ok(packet) = cap.next_packet() {
        count += 1;
        let sec = packet.header.ts.tv_sec;
        let usec = packet.header.ts.tv_usec;
        let ts = match Utc.timestamp_opt(sec, (usec * 1000) as u32).single() {
            Some(t) => t,
            None => {
                warn!(
                    "Invalid timestamp in packet {}: sec={}, usec={}. Skipping packet.",
                    count, sec, usec
                );
                continue;
            }
        };
        let pkt_info = parse_packet(packet.data, ts, packet.header.len);
        all_packets.push(pkt_info);
        debug!("Parsed packet {}", count);
        if count % 10000 == 0 {
            info!("Processed {} packets...", count);
        }
    }
    info!("Total packets read: {}", count);

    // Phase 3: Flow identification and aggregation
    let mut flows: HashMap<FlowKey, FlowData> = HashMap::new();
    let mut timed_out_flows: HashMap<FlowKey, FlowData> = HashMap::new();
    let mut packet_count_since_timeout_check = 0;
    let tcp_timeout = chrono::Duration::seconds(config.flow.tcp_timeout_secs as i64);
    let udp_timeout = chrono::Duration::seconds(config.flow.udp_timeout_secs as i64);
    let check_interval = config.flow.check_interval;

    for pkt in &mut all_packets {
        if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port), Some(protocol)) = (
            pkt.src_ip,
            pkt.dst_ip,
            pkt.src_port,
            pkt.dst_port,
            pkt.protocol,
        ) {
            if let Some(key) = FlowKey::new(src_ip, dst_ip, src_port, dst_port, protocol) {
                let flow_id = key.to_string_id();
                pkt.flow_id = Some(flow_id.clone());
                let entry = flows.entry(key).or_insert_with(|| FlowData {
                    start_time: pkt.timestamp,
                    end_time: pkt.timestamp,
                    last_seen: pkt.timestamp,
                    packet_count: 0,
                    byte_count: 0,
                    packets: Vec::new(),
                    label: None,
                    attack_type: None,
                    suricata_alerts: Vec::new(),
                });
                entry.packet_count += 1;
                entry.byte_count += pkt.length as u64;
                entry.end_time = pkt.timestamp;
                entry.last_seen = pkt.timestamp;
                entry.packets.push(pkt.clone());
            }
        }

        // Check for flow timeouts periodically
        packet_count_since_timeout_check += 1;
        if packet_count_since_timeout_check >= check_interval {
            let current_time = pkt.timestamp;
            let mut keys_to_remove = Vec::new();

            // Identify timed-out flows
            for (key, flow) in &flows {
                let timeout = if key.protocol == 6 {
                    tcp_timeout
                } else {
                    udp_timeout
                };
                let age = current_time.signed_duration_since(flow.last_seen);

                if age > timeout {
                    keys_to_remove.push(key.clone());
                }
            }

            // Move timed-out flows to the timed_out_flows map
            if !keys_to_remove.is_empty() {
                debug!("Found {} timed-out flows", keys_to_remove.len());
                for key in keys_to_remove {
                    if let Some(flow) = flows.remove(&key) {
                        timed_out_flows.insert(key, flow);
                    }
                }
            }

            packet_count_since_timeout_check = 0;
        }
    }
    info!("Total flows identified: {}", flows.len());
    info!("Total timed-out flows: {}", timed_out_flows.len());

    // Apply label rules to flows and packets
    let mut flow_labels: HashMap<String, String> = HashMap::new();
    // Apply labels to active flows
    for (key, data) in &mut flows {
        for rule in &label_rules {
            let matched = match &rule.rule {
                LabelType::IpAddr(ip) => key.ip_a == *ip || key.ip_b == *ip,
                LabelType::FlowId(fid) => key.to_string_id() == *fid,
                LabelType::Subnet(net) => net.contains(key.ip_a) || net.contains(key.ip_b),
                LabelType::Port(p) => key.port_a == *p || key.port_b == *p,
            };
            if matched {
                data.label = Some(rule.label.clone());
                flow_labels.insert(key.to_string_id(), rule.label.clone());
                break;
            }
        }
    }

    // Apply labels to timed-out flows
    for (key, data) in &mut timed_out_flows {
        for rule in &label_rules {
            let matched = match &rule.rule {
                LabelType::IpAddr(ip) => key.ip_a == *ip || key.ip_b == *ip,
                LabelType::FlowId(fid) => key.to_string_id() == *fid,
                LabelType::Subnet(net) => net.contains(key.ip_a) || net.contains(key.ip_b),
                LabelType::Port(p) => key.port_a == *p || key.port_b == *p,
            };
            if matched {
                data.label = Some(rule.label.clone());
                flow_labels.insert(key.to_string_id(), rule.label.clone());
                break;
            }
        }
    }
    // Propagate labels to all_packets
    for pkt in &mut all_packets {
        if let Some(fid) = &pkt.flow_id {
            if let Some(lab) = flow_labels.get(fid) {
                pkt.label = Some(lab.clone());
            }
        }
    }

    // Perform attack detection if enabled
    if detect_attacks {
        info!("Running attack detection heuristics...");
        let detected = run_attack_detection(
            &flows,
            &all_packets,
            cli.scan_threshold,
            cli.udp_scan_threshold,
            &config.detection,
        );
        if !detected.is_empty() {
            info!("Detected {} potential attack flows", detected.len());

            // Apply attack labels to flows
            for (flow_id, attack_type) in &detected {
                for (key, data) in &mut flows {
                    if key.to_string_id() == *flow_id {
                        data.attack_type = Some(attack_type.clone());
                        // Apply label based on configured format if no existing label
                        if data.label.is_none() {
                            let label = config
                                .detection
                                .labels
                                .attack_format
                                .replace("{type}", attack_type);
                            data.label = Some(label);
                        }
                        break;
                    }
                }
            }
        } else {
            info!("No attacks detected");
        }
    }

    // Correlate Suricata alerts with flows if enabled
    if let Some(suricata_alerts_path) = &cli.suricata_alerts {
        if config.suricata.enabled {
            info!("Correlating Suricata alerts with flows...");
            let alerts = parse_suricata_alerts(suricata_alerts_path)?;
            let matched = correlate_alerts_with_flows(&alerts, &mut flows);
            info!("Matched {} Suricata alerts to flows", matched);
        } else {
            info!("Suricata alert correlation is disabled in configuration");
        }
    }

    // Output results
    let stem = cli
        .input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    if cli.csv {
        let csv_path = cli.output_dir.join(format!("{}.csv", stem));
        write_packet_csv(&all_packets, &csv_path)?;
        info!("Wrote CSV output to {:?}", csv_path);
    }
    if cli.json {
        let json_path = cli.output_dir.join(format!("{}.json", stem));
        // Combine active and timed-out flows for JSON output
        let mut all_flows = flows.clone();
        all_flows.extend(timed_out_flows);
        write_flow_json(&all_flows, &json_path)?;
        info!("Wrote JSON output to {:?}", json_path);
    }

    if !cli.csv && !cli.json {
        warn!(
            "No output format specified (use --csv and/or --json). Processing complete, but no files generated."
        );
    }

    Ok(())
}

// Label rule definitions and parsing
#[derive(Debug)]
enum LabelType {
    IpAddr(IpAddr),
    FlowId(String),
    Subnet(IpNetwork),
    Port(u16),
}

#[derive(Debug)]
struct LabelRule {
    rule: LabelType,
    label: String,
}

/// Parse label rules from a CSV file (type,criteria,label)
fn parse_label_rules(path: &Path) -> Result<Vec<LabelRule>, Box<dyn Error>> {
    let mut rdr = ReaderBuilder::new().has_headers(false).from_path(path)?;
    let mut rules = Vec::new();
    for (idx, result) in rdr.records().enumerate() {
        let record = result?;
        // Expect exactly 3 fields: type, criteria, label
        if record.len() < 3 {
            warn!(
                "Skipping invalid label rule at line {}: expected 3 fields, got {}",
                idx + 1,
                record.len()
            );
            continue;
        }
        let typ = record.get(0).unwrap().trim();
        let crit = record.get(1).unwrap().trim();
        let lab = record.get(2).unwrap().trim().to_string();
        if lab.is_empty() {
            warn!(
                "Skipping label rule at line {}: label cannot be empty",
                idx + 1
            );
            continue;
        }
        match typ {
            "ip_addr" => match IpAddr::from_str(crit) {
                Ok(ip) => rules.push(LabelRule {
                    rule: LabelType::IpAddr(ip),
                    label: lab.clone(),
                }),
                Err(e) => warn!(
                    "Invalid IP '{}' in label rule at line {}: {}",
                    crit,
                    idx + 1,
                    e
                ),
            },
            "flow_id" => {
                rules.push(LabelRule {
                    rule: LabelType::FlowId(crit.to_string()),
                    label: lab.clone(),
                });
            }
            "subnet" => match IpNetwork::from_str(crit) {
                Ok(net) => rules.push(LabelRule {
                    rule: LabelType::Subnet(net),
                    label: lab.clone(),
                }),
                Err(e) => warn!(
                    "Invalid subnet '{}' in label rule at line {}: {}",
                    crit,
                    idx + 1,
                    e
                ),
            },
            "port" => match crit.parse::<u16>() {
                Ok(p) => rules.push(LabelRule {
                    rule: LabelType::Port(p),
                    label: lab.clone(),
                }),
                Err(e) => warn!(
                    "Invalid port '{}' in label rule at line {}: {}",
                    crit,
                    idx + 1,
                    e
                ),
            },
            _ => {
                warn!("Unknown label type '{}' at line {}", typ, idx + 1);
            }
        }
    }
    Ok(rules)
}

/// Detect potential attacks using heuristics
fn run_attack_detection(
    flows: &HashMap<FlowKey, FlowData>,
    packets: &[PacketInfo],
    scan_threshold: usize,
    udp_scan_threshold: usize,
    config: &DetectionConfig,
) -> HashMap<String, String> {
    let mut attack_flows: HashMap<String, String> = HashMap::new();
    let mut source_stats: HashMap<IpAddr, SourceStats> = HashMap::new();

    // First pass: gather statistics per source IP
    for pkt in packets {
        if let (Some(src_ip), Some(dst_ip), Some(dst_port), Some(protocol)) =
            (pkt.src_ip, pkt.dst_ip, pkt.dst_port, pkt.protocol)
        {
            let stats = source_stats.entry(src_ip).or_default();
            stats.packet_count += 1;
            stats.dst_ips.insert(dst_ip);
            stats.dst_ports.entry(dst_ip).or_default().insert(dst_port);
            stats
                .dst_ips_per_port
                .entry(dst_port)
                .or_default()
                .insert(dst_ip);

            // Track SYN packets for TCP
            if protocol == 6 {
                // TCP
                if let Some(tcp_flags) = pkt.tcp_flags {
                    // TCP SYN flag (bit 1), ACK flag (bit 4)
                    let syn_flag = tcp_flags & 0x02 != 0;
                    let ack_flag = tcp_flags & 0x10 != 0;

                    // SYN without ACK - Initial connection attempt
                    if syn_flag && !ack_flag {
                        *stats.syn_packets.entry(dst_ip).or_default() += 1;
                    }
                    // ACK without SYN - Likely connection establishment or data
                    if ack_flag && !syn_flag {
                        // For simplicity, we'll count any non-SYN ACK from client to server
                        // as potentially completing a handshake. This is an approximation.
                        // A more accurate approach would track each connection state.
                        stats
                            .successful_connections
                            .entry(dst_ip)
                            .or_default()
                            .insert(dst_port);
                    }
                }
            }

            // For SYN flood detection, track timestamps of SYN packets to specific services
            if protocol == 6 {
                // TCP
                if let Some(tcp_flags) = pkt.tcp_flags {
                    // Check if SYN flag is set (bit 1) in TCP flags
                    if tcp_flags & 0x02 != 0 {
                        source_stats
                            .entry(src_ip)
                            .or_default()
                            .syn_timestamps
                            .entry((dst_ip, dst_port))
                            .or_default()
                            .push(pkt.timestamp);
                    }
                }
            }

            // Track ICMP Echo Request packets for ping sweep detection
            if protocol == 1 {
                // ICMP
                // Check if this is an Echo Request (ping) packet - type 8, code 0
                if let (Some(icmp_type), Some(icmp_code)) = (pkt.icmp_type, pkt.icmp_code) {
                    if icmp_type == 8 && icmp_code == 0 {
                        // Echo Request (ping)
                        if let Some(ping_stats) = source_stats.get_mut(&src_ip) {
                            *ping_stats.ping_packets.entry(dst_ip).or_default() += 1;
                        }
                    }
                }
            } else if protocol == 58 {
                // ICMPv6
                // ICMPv6 Echo Request is type 128
                if let (Some(icmp_type), Some(icmp_code)) = (pkt.icmp_type, pkt.icmp_code) {
                    if icmp_type == 128 && icmp_code == 0 {
                        // Echo Request (ping)
                        if let Some(ping_stats) = source_stats.get_mut(&src_ip) {
                            *ping_stats.ping_packets.entry(dst_ip).or_default() += 1;
                        }
                    }
                }
            }
        }
    }

    // Second pass: apply detection heuristics
    for (src_ip, stats) in source_stats {
        // TCP SYN scan detection
        if config.heuristics.syn_scan.enabled {
            for (dst_ip, port_set) in &stats.dst_ports {
                // Skip if we've already detected a scan for this source->dest pair
                if attack_flows.values().any(|attack_type| {
                    attack_type == &AttackType::TcpSynScan.to_string()
                        && find_flow_id_for_scan(src_ip, *dst_ip, flows).is_some()
                }) {
                    continue;
                }

                // If source connected to many TCP ports on the same destination
                if protocol_for_ip_pair(src_ip, *dst_ip, flows) == Some(6) && // TCP
                   port_set.len() >= scan_threshold
                {
                    // Check if there were SYN packets sent to this destination
                    if let Some(syn_count) = stats.syn_packets.get(dst_ip) {
                        if *syn_count >= port_set.len() as u32 / 2 {
                            // At least half of connections were SYN
                            // Find the flow ID for this potential scan
                            if let Some(flow_id) = find_flow_id_for_scan(src_ip, *dst_ip, flows) {
                                attack_flows.insert(flow_id, AttackType::TcpSynScan.to_string());
                                debug!(
                                    "Detected TCP SYN scan from {} to {} ({} ports)",
                                    src_ip,
                                    dst_ip,
                                    port_set.len()
                                );
                            }
                        }
                    }
                }
            }
        }

        // TCP Connect scan detection
        if config.heuristics.connect_scan.enabled {
            for (dst_ip, port_set) in &stats.dst_ports {
                // Skip if we've already detected a SYN scan for this source->dest pair
                if attack_flows.values().any(|attack_type| {
                    attack_type == &AttackType::TcpSynScan.to_string()
                        && find_flow_id_for_scan(src_ip, *dst_ip, flows).is_some()
                }) {
                    continue;
                }

                // If source connected to many TCP ports on the same destination
                if protocol_for_ip_pair(src_ip, *dst_ip, flows) == Some(6) && // TCP
                   port_set.len() >= scan_threshold
                {
                    // Get established connections to this destination
                    if let Some(established_ports) = stats.successful_connections.get(dst_ip) {
                        // If many ports have established connections, likely a connect scan
                        if established_ports.len() >= scan_threshold {
                            // Find the flow ID for this potential scan
                            if let Some(flow_id) = find_flow_id_for_scan(src_ip, *dst_ip, flows) {
                                attack_flows
                                    .insert(flow_id, AttackType::TcpConnectScan.to_string());
                                debug!(
                                    "Detected TCP Connect scan from {} to {} ({} ports)",
                                    src_ip,
                                    dst_ip,
                                    established_ports.len()
                                );
                            }
                        }
                    }
                }
            }
        }

        // UDP scan detection
        if config.heuristics.udp_scan.enabled {
            for (dst_ip, port_set) in &stats.dst_ports {
                // Skip if we've already detected a scan for this source->dest pair
                if attack_flows.values().any(|attack_type| {
                    attack_type == &AttackType::UdpScan.to_string()
                        && find_flow_id_for_scan(src_ip, *dst_ip, flows).is_some()
                }) {
                    continue;
                }

                // If source connected to many UDP ports on the same destination
                if protocol_for_ip_pair(src_ip, *dst_ip, flows) == Some(17) && // UDP
                   port_set.len() >= udp_scan_threshold
                {
                    // UDP scans typically have fewer ports than TCP scans
                    // UDP scan detection is simpler since we don't have handshake flags
                    if let Some(flow_id) = find_flow_id_for_scan(src_ip, *dst_ip, flows) {
                        attack_flows.insert(flow_id, AttackType::UdpScan.to_string());
                        debug!(
                            "Detected UDP scan from {} to {} ({} ports)",
                            src_ip,
                            dst_ip,
                            port_set.len()
                        );
                    }
                }
            }
        }

        // SYN flood detection
        if config.heuristics.syn_flood.enabled {
            // Get the window size in seconds for SYN flood detection
            let window_secs =
                chrono::Duration::seconds(config.heuristics.syn_flood.time_window_secs as i64);
            let threshold = config.heuristics.syn_flood.rate_threshold;

            // Look for SYN flood patterns in the SYN timestamps
            for ((dst_ip, dst_port), timestamps) in &stats.syn_timestamps {
                // Skip if we don't have enough SYNs to even consider a flood
                if timestamps.len() < threshold as usize {
                    continue;
                }

                // Calculate SYN rate over the configured time window
                let mut highest_rate = 0;
                let mut window_start = 0;
                let mut window_end = 0;

                // Sort timestamps to ensure they're in chronological order
                let mut sorted_timestamps = timestamps.clone();
                sorted_timestamps.sort();

                // Sliding window analysis for SYN rate
                while window_end < sorted_timestamps.len() {
                    // Expand window end as long as it's within the time window
                    while window_end < sorted_timestamps.len()
                        && sorted_timestamps[window_end]
                            .signed_duration_since(sorted_timestamps[window_start])
                            <= window_secs
                    {
                        window_end += 1;
                    }

                    // Calculate rate in this window
                    let window_size = window_end - window_start;
                    if window_size > highest_rate {
                        highest_rate = window_size;
                    }

                    // Slide window start
                    window_start += 1;
                }

                // Check if we found a SYN flood
                if highest_rate >= threshold as usize {
                    // Find any flow between these IPs to associate the flood with
                    if let Some(flow_id) =
                        find_flow_id_for_service(src_ip, *dst_ip, *dst_port, flows)
                    {
                        attack_flows.insert(flow_id, AttackType::SynFlood.to_string());
                        debug!(
                            "Detected SYN flood from {} to {}:{} ({} SYNs in {} seconds)",
                            src_ip,
                            dst_ip,
                            dst_port,
                            highest_rate,
                            config.heuristics.syn_flood.time_window_secs
                        );
                    }
                }
            }
        }

        // Port sweep detection - look for sources accessing many destinations on the same port
        if config.heuristics.port_sweep.enabled {
            let port_sweep_threshold = config.heuristics.port_sweep.threshold;

            // Check each source port for many destinations
            for (port, dst_ips) in &stats.dst_ips_per_port {
                // Skip if we don't have enough distinct destinations
                if dst_ips.len() < port_sweep_threshold {
                    continue;
                }

                // Check if we can find a flow to associate this sweep with
                // Note: For port sweeps, we need a more sophisticated way to represent the activity
                // since it spans multiple flows. Here, we'll just pick a representative flow.
                if let Some(dst_ip) = dst_ips.iter().next() {
                    if let Some(flow_id) = find_flow_id_for_service(src_ip, *dst_ip, *port, flows) {
                        attack_flows.insert(flow_id, AttackType::PortSweep.to_string());
                        debug!(
                            "Detected port sweep from {} on port {} ({} destinations)",
                            src_ip,
                            port,
                            dst_ips.len()
                        );
                    }
                }
            }
        }

        // Ping sweep detection - look for sources sending many ICMP Echo Requests
        if config.heuristics.ping_sweep.enabled {
            let ping_sweep_threshold = config.heuristics.ping_sweep.threshold;

            // Check for sources sending pings to many different destinations
            if stats.ping_packets.len() >= ping_sweep_threshold {
                // Find a representative flow to associate with this ping sweep
                // We'll use the first ping target as the representative
                if let Some(dst_ip) = stats.ping_packets.keys().next() {
                    if let Some(flow_id) = find_flow_id_for_ping(src_ip, *dst_ip, flows) {
                        attack_flows.insert(flow_id, AttackType::PingSweep.to_string());
                        debug!(
                            "Detected ping sweep from {} to {} different targets",
                            src_ip,
                            stats.ping_packets.len()
                        );
                    }
                }
            }
        }
    }

    attack_flows
}

/// Find the protocol used between two IPs in the flows
fn protocol_for_ip_pair(
    ip_a: IpAddr,
    ip_b: IpAddr,
    flows: &HashMap<FlowKey, FlowData>,
) -> Option<u8> {
    for key in flows.keys() {
        if (key.ip_a == ip_a && key.ip_b == ip_b) || (key.ip_a == ip_b && key.ip_b == ip_a) {
            return Some(key.protocol);
        }
    }
    None
}

/// Find a flow ID for a scan between two IPs
fn find_flow_id_for_scan(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    flows: &HashMap<FlowKey, FlowData>,
) -> Option<String> {
    for key in flows.keys() {
        // We want to find any flow between these two IPs to associate the scan with
        if (key.ip_a == src_ip && key.ip_b == dst_ip) || (key.ip_a == dst_ip && key.ip_b == src_ip)
        {
            return Some(key.to_string_id());
        }
    }
    None
}

/// Find a flow ID for a specific service (IP+port)
fn find_flow_id_for_service(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    flows: &HashMap<FlowKey, FlowData>,
) -> Option<String> {
    for key in flows.keys() {
        // Find flows to the specific destination service
        if (key.ip_a == src_ip && key.ip_b == dst_ip && key.port_b == dst_port)
            || (key.ip_b == src_ip && key.ip_a == dst_ip && key.port_a == dst_port)
        {
            return Some(key.to_string_id());
        }
    }
    None
}

/// Find a flow ID for ICMP ping traffic between two IPs
fn find_flow_id_for_ping(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    flows: &HashMap<FlowKey, FlowData>,
) -> Option<String> {
    for (key, flow_data) in flows {
        // For ICMP, we're looking for the specific protocol (1 or 58) and matching IPs
        if (key.protocol == 1 || key.protocol == 58) && // ICMP or ICMPv6
           ((key.ip_a == src_ip && key.ip_b == dst_ip) ||
            (key.ip_b == src_ip && key.ip_a == dst_ip))
        {
            return Some(key.to_string_id());
        }
    }
    None
}

/// Represents a Suricata alert from EVE JSON format
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuricataAlert {
    /// Timestamp from Suricata
    pub timestamp: String,
    /// Alert signature ID
    pub signature_id: u32,
    /// Alert signature name
    pub signature: String,
    /// Alert category
    pub category: String,
    /// Alert severity (1-4, with 1 being highest)
    pub severity: u8,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port (if applicable)
    pub src_port: Option<u16>,
    /// Destination port (if applicable)
    pub dst_port: Option<u16>,
    /// Protocol number
    pub proto: Option<u8>,
}

/// Wrapper function for correlate_suricata_alerts to maintain API compatibility with tests
pub fn correlate_alerts_with_flows(
    alerts: &[SuricataAlert],
    flows: &mut HashMap<FlowKey, FlowData>,
) -> usize {
    // Create a default config for test compatibility
    let default_config = SuricataConfig {
        enabled: true,
        alert_format: "{signature}".to_string(),
    };

    correlate_suricata_alerts(flows, alerts, &default_config)
}

/// Parse Suricata EVE JSON alerts and return a vector of alerts
pub fn parse_suricata_alerts(path: &Path) -> Result<Vec<SuricataAlert>, Box<dyn Error>> {
    // Use a mutex to enable thread-safe concurrent access to alerts vector
    let alerts = Mutex::new(Vec::new());
    let file = File::open(path)?;
    info!("Reading Suricata EVE JSON file: {:?}", path);
    let mut content = String::new();
    BufReader::new(file).read_to_string(&mut content)?;
    info!(
        "Processing {} EVE JSON lines in parallel",
        content.lines().count()
    );
    let lines: Vec<&str> = content.lines().collect();
    lines.par_iter().for_each(|line| {
        if let Ok(json_value) = serde_json::from_str::<Value>(line) {
            if json_value["event_type"] == "alert" {
                // Only process alert events

                // Required fields for a valid alert
                let timestamp = json_value["timestamp"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();

                // Extract alert details
                let signature_id = json_value["alert"]["signature_id"].as_u64().unwrap_or(0) as u32;
                let signature = json_value["alert"]["signature"]
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string();
                let category = json_value["alert"]["category"]
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string();
                let severity = json_value["alert"]["severity"].as_u64().unwrap_or(0) as u8;

                // Extract flow details
                let src_ip_str = json_value["src_ip"].as_str().unwrap_or("0.0.0.0");
                let dst_ip_str = json_value["dest_ip"].as_str().unwrap_or("0.0.0.0");

                // Parse IP addresses
                let src_ip = src_ip_str
                    .parse::<IpAddr>()
                    .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
                let dst_ip = dst_ip_str
                    .parse::<IpAddr>()
                    .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

                // Optional port and protocol information
                let src_port = json_value["src_port"].as_u64().map(|p| p as u16);
                let dst_port = json_value["dest_port"].as_u64().map(|p| p as u16);
                let proto = json_value["proto"].as_str().map(|p| match p {
                    "TCP" | "tcp" => 6,
                    "UDP" | "udp" => 17,
                    "ICMP" | "icmp" => 1,
                    _ => 0,
                });

                // Add to shared alerts vector with mutex
                if let Ok(mut alert_vec) = alerts.lock() {
                    alert_vec.push(SuricataAlert {
                        timestamp,
                        signature_id,
                        signature,
                        category,
                        severity,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        proto,
                    });
                }
            }
        }
    });
    // Extract result from mutex
    let result = match alerts.into_inner() {
        Ok(alerts) => alerts,
        Err(e) => return Err(format!("Mutex error: {:?}", e).into()),
    };

    info!("Processed {} Suricata alerts", result.len());
    Ok(result)
}

/// Match Suricata alerts to flows based on IP addresses, ports, and protocol
pub fn correlate_suricata_alerts(
    flows: &mut HashMap<FlowKey, FlowData>,
    alerts: &[SuricataAlert],
    config: &SuricataConfig,
) -> usize {
    let match_count = AtomicUsize::new(0);

    // Group alerts by IP pairs for faster matching
    info!(
        "Organizing {} alerts for efficient correlation",
        alerts.len()
    );
    let mut alerts_by_ip: HashMap<(IpAddr, IpAddr), Vec<&SuricataAlert>> = HashMap::new();
    for alert in alerts {
        let key = (alert.src_ip, alert.dst_ip);
        alerts_by_ip.entry(key).or_default().push(alert);

        // Also add reverse direction for bidirectional matching
        let rev_key = (alert.dst_ip, alert.src_ip);
        alerts_by_ip.entry(rev_key).or_default().push(alert);
    }

    // Collect matches that we want to apply
    // Create a thread-safe vector to collect matches from parallel processing
    let matches_to_apply = Mutex::new(Vec::<(FlowKey, SuricataAlert, String)>::new());

    // First, find all matches in parallel without modifying flows
    let flow_keys: Vec<FlowKey> = flows.keys().cloned().collect();

    flow_keys.par_iter().for_each(|key| {
        // Check if we have any alerts for this IP pair
        if let Some(relevant_alerts) = alerts_by_ip.get(&(key.ip_a, key.ip_b)) {
            for alert in relevant_alerts {
                // Check protocol match
                let proto_match = match alert.proto {
                    Some(p) => key.protocol == p,
                    None => true, // If alert doesn't specify protocol, consider it a match
                };

                if !proto_match {
                    continue;
                }

                // Only check ports if both alert and flow have port information
                let port_match = match (alert.src_port, alert.dst_port) {
                    (Some(src_p), Some(dst_p)) => {
                        (key.port_a == src_p && key.port_b == dst_p)
                            || (key.port_a == dst_p && key.port_b == src_p)
                    }
                    _ => true, // If alert doesn't have port info, consider it a match
                };

                if !port_match {
                    continue;
                }

                // IP match is already confirmed by our hashmap lookup
                let ip_match = (key.ip_a == alert.src_ip && key.ip_b == alert.dst_ip)
                    || (key.ip_b == alert.src_ip && key.ip_a == alert.dst_ip);

                // If all criteria match, collect this match
                if ip_match {
                    // Format the alert string using the configured format
                    let alert_str = config
                        .alert_format
                        .replace("{signature}", &alert.signature)
                        .replace("{alert_category}", &alert.category)
                        .replace("{severity}", &alert.severity.to_string())
                        .replace("{signature_id}", &alert.signature_id.to_string());

                    // Add to collection of matches in a thread-safe way
                    if let Ok(mut matches) = matches_to_apply.lock() {
                        matches.push((key.clone(), (*alert).clone(), alert_str));
                        match_count.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            }
        }
    });

    // Now, apply all collected matches with single mutable access to flows
    if let Ok(collected_matches) = matches_to_apply.into_inner() {
        for (key, alert, alert_str) in collected_matches {
            if let Some(flow_data) = flows.get_mut(&key) {
                flow_data.suricata_alerts.push(alert);

                // If no other attack type is set, label this flow
                if flow_data.attack_type.is_none() {
                    flow_data.attack_type = Some(alert_str);
                }
            }
        }
    }

    info!("Alert correlation complete");
    match_count.load(AtomicOrdering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::NamedTempFile;

    #[test]
    fn test_flowkey_canonicalization() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let key1 = FlowKey::new(ip1, ip2, 1000, 2000, 6).unwrap();
        let key2 = FlowKey::new(ip2, ip1, 2000, 1000, 6).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key1.ip_a, ip1);
        assert_eq!(key1.ip_b, ip2);
        assert_eq!(key1.port_a, 1000);
        assert_eq!(key1.port_b, 2000);
        assert_eq!(key1.protocol, 6);
    }

    #[test]
    fn test_parse_label_rules() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "ip_addr,127.0.0.1,local").unwrap();
        writeln!(file, "port,80,http").unwrap();
        file.flush().unwrap();
        let rules = parse_label_rules(file.path()).unwrap();
        assert_eq!(rules.len(), 2);
        match &rules[0].rule {
            LabelType::IpAddr(ip) => assert_eq!(*ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            _ => panic!("Expected IpAddr rule"),
        }
        match &rules[1].rule {
            LabelType::Port(p) => assert_eq!(*p, 80),
            _ => panic!("Expected Port rule"),
        }
    }

    #[test]
    fn test_write_flow_json() {
        let mut flows = HashMap::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let key = FlowKey::new(ip1, ip2, 1000, 2000, 6).unwrap();
        let data = FlowData {
            start_time: Utc::now(),
            end_time: Utc::now(),
            last_seen: Utc::now(),
            packet_count: 1,
            byte_count: 100,
            packets: Vec::new(),
            label: Some("test".to_string()),
            attack_type: None,
            suricata_alerts: Vec::new(),
        };
        flows.insert(key.clone(), data.clone());
        let tmp = NamedTempFile::new().unwrap();
        write_flow_json(&flows, tmp.path()).unwrap();
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let v: Value = serde_json::from_str(&content).unwrap();
        let id = key.to_string_id();
        assert!(v.get(&id).is_some());
        assert_eq!(v[&id]["packet_count"], serde_json::json!(data.packet_count));
    }
}
