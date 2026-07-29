//! PCAP validation module for checking replay-ability
//!
//! Quick validation of pcap files to determine if they are suitable for replay.
//! Checks packet count, IP diversity, protocol distribution, and other metrics.

use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
use pcap::Capture;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "validate",
    about = "Validate PCAP files for replay-ability"
)]
pub struct ValidateCli {
    /// Input PCAP file
    #[arg(short, long, value_name = "PCAP")]
    pub input: PathBuf,

    /// Maximum packets to sample (0 = all)
    #[arg(short = 'n', long, default_value = "10000")]
    pub sample_size: usize,

    /// Minimum required packets for valid pcap
    #[arg(long, default_value = "10")]
    pub min_packets: usize,

    /// Minimum required unique IPs
    #[arg(long, default_value = "2")]
    pub min_unique_ips: usize,

    /// Output JSON report
    #[arg(short = 'j', long)]
    pub json: bool,

    /// Quiet mode - only output exit code
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

#[derive(Debug, Serialize)]
pub struct ValidationReport {
    pub file_path: String,
    pub valid: bool,
    pub issues: Vec<String>,
    pub stats: PcapStats,
}

#[derive(Debug, Default, Serialize)]
pub struct PcapStats {
    pub total_packets: usize,
    pub sampled_packets: usize,
    pub unique_src_ips: usize,
    pub unique_dst_ips: usize,
    pub unique_ip_pairs: usize,
    pub protocols: HashMap<String, usize>,
    pub avg_packet_size: f64,
    pub min_packet_size: usize,
    pub max_packet_size: usize,
    pub capture_duration_secs: f64,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
    pub has_ip_layer: bool,
    pub has_tcp: bool,
    pub has_udp: bool,
    pub non_ip_packets: usize,
    pub malformed_packets: usize,
}

pub fn run(cli: ValidateCli) -> Result<(), Box<dyn Error>> {
    let report = validate_pcap(&cli)?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !cli.quiet {
        print_report(&report);
    }

    // Exit with code 1 if not valid (for scripting)
    if !report.valid {
        std::process::exit(1);
    }

    Ok(())
}

fn print_report(report: &ValidationReport) {
    println!("PCAP Validation Report");
    println!("======================");
    println!("File: {}", report.file_path);
    println!("Valid: {}", if report.valid { "YES" } else { "NO" });
    println!();

    if !report.issues.is_empty() {
        println!("Issues:");
        for issue in &report.issues {
            println!("  - {}", issue);
        }
        println!();
    }

    println!("Statistics:");
    println!("  Total packets: {}", report.stats.total_packets);
    println!("  Sampled packets: {}", report.stats.sampled_packets);
    println!("  Unique source IPs: {}", report.stats.unique_src_ips);
    println!("  Unique dest IPs: {}", report.stats.unique_dst_ips);
    println!("  Unique IP pairs: {}", report.stats.unique_ip_pairs);
    println!("  Avg packet size: {:.1} bytes", report.stats.avg_packet_size);
    println!(
        "  Packet size range: {}-{} bytes",
        report.stats.min_packet_size, report.stats.max_packet_size
    );
    println!(
        "  Capture duration: {:.2} seconds",
        report.stats.capture_duration_secs
    );
    println!("  Has IP layer: {}", report.stats.has_ip_layer);
    println!("  Has TCP: {}", report.stats.has_tcp);
    println!("  Has UDP: {}", report.stats.has_udp);
    println!("  Non-IP packets: {}", report.stats.non_ip_packets);
    println!("  Malformed packets: {}", report.stats.malformed_packets);
    println!();

    if !report.stats.protocols.is_empty() {
        println!("Protocols:");
        let mut protocols: Vec<_> = report.stats.protocols.iter().collect();
        protocols.sort_by(|a, b| b.1.cmp(a.1));
        for (proto, count) in protocols {
            let pct = (*count as f64 / report.stats.sampled_packets as f64) * 100.0;
            println!("  {}: {} ({:.1}%)", proto, count, pct);
        }
    }
}

pub fn validate_pcap(cli: &ValidateCli) -> Result<ValidationReport, Box<dyn Error>> {
    let mut cap = Capture::from_file(&cli.input)?;
    let file_path = cli.input.to_string_lossy().to_string();

    let mut stats = PcapStats::default();
    let mut issues = Vec::new();

    let mut src_ips: HashSet<IpAddr> = HashSet::new();
    let mut dst_ips: HashSet<IpAddr> = HashSet::new();
    let mut ip_pairs: HashSet<(IpAddr, IpAddr)> = HashSet::new();
    let mut total_bytes: u64 = 0;
    let mut first_ts: Option<DateTime<Utc>> = None;
    let mut last_ts: Option<DateTime<Utc>> = None;

    let mut packet_count = 0usize;

    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;

        // Sample limit
        if cli.sample_size > 0 && packet_count > cli.sample_size {
            break;
        }

        let len = packet.data.len();
        total_bytes += len as u64;

        if stats.min_packet_size == 0 || len < stats.min_packet_size {
            stats.min_packet_size = len;
        }
        if len > stats.max_packet_size {
            stats.max_packet_size = len;
        }

        // Parse timestamp
        let ts_secs = packet.header.ts.tv_sec as i64;
        let ts_usecs = packet.header.ts.tv_usec as u32;
        if let Some(ts) = Utc.timestamp_opt(ts_secs, ts_usecs * 1000).single() {
            if first_ts.is_none() {
                first_ts = Some(ts);
            }
            last_ts = Some(ts);
        }

        // Parse ethernet
        if let Some(eth) = EthernetPacket::new(packet.data) {
            match eth.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                        stats.has_ip_layer = true;
                        let src = IpAddr::V4(ipv4.get_source());
                        let dst = IpAddr::V4(ipv4.get_destination());
                        src_ips.insert(src);
                        dst_ips.insert(dst);
                        ip_pairs.insert((src, dst));

                        let proto = ipv4.get_next_level_protocol();
                        let proto_name = match proto.0 {
                            6 => {
                                stats.has_tcp = true;
                                "TCP"
                            }
                            17 => {
                                stats.has_udp = true;
                                "UDP"
                            }
                            1 => "ICMP",
                            _ => "Other",
                        };
                        *stats.protocols.entry(proto_name.to_string()).or_insert(0) += 1;
                    } else {
                        stats.malformed_packets += 1;
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                        stats.has_ip_layer = true;
                        let src = IpAddr::V6(ipv6.get_source());
                        let dst = IpAddr::V6(ipv6.get_destination());
                        src_ips.insert(src);
                        dst_ips.insert(dst);
                        ip_pairs.insert((src, dst));

                        let proto = ipv6.get_next_header();
                        let proto_name = match proto.0 {
                            6 => {
                                stats.has_tcp = true;
                                "TCP"
                            }
                            17 => {
                                stats.has_udp = true;
                                "UDP"
                            }
                            58 => "ICMPv6",
                            _ => "Other",
                        };
                        *stats.protocols.entry(proto_name.to_string()).or_insert(0) += 1;
                    } else {
                        stats.malformed_packets += 1;
                    }
                }
                EtherTypes::Arp => {
                    stats.non_ip_packets += 1;
                    *stats.protocols.entry("ARP".to_string()).or_insert(0) += 1;
                }
                _ => {
                    stats.non_ip_packets += 1;
                    *stats
                        .protocols
                        .entry(format!("0x{:04x}", eth.get_ethertype().0))
                        .or_insert(0) += 1;
                }
            }
        } else {
            stats.malformed_packets += 1;
        }
    }

    // Finalize stats
    stats.total_packets = packet_count;
    stats.sampled_packets = packet_count.min(cli.sample_size);
    if cli.sample_size == 0 {
        stats.sampled_packets = packet_count;
    }
    stats.unique_src_ips = src_ips.len();
    stats.unique_dst_ips = dst_ips.len();
    stats.unique_ip_pairs = ip_pairs.len();

    if packet_count > 0 {
        stats.avg_packet_size = total_bytes as f64 / packet_count as f64;
    }

    if let (Some(first), Some(last)) = (first_ts, last_ts) {
        stats.capture_duration_secs = (last - first).num_milliseconds() as f64 / 1000.0;
        stats.first_timestamp = Some(first.to_rfc3339());
        stats.last_timestamp = Some(last.to_rfc3339());
    }

    // Validation checks
    if packet_count < cli.min_packets {
        issues.push(format!(
            "Too few packets: {} (minimum: {})",
            packet_count, cli.min_packets
        ));
    }

    let total_unique_ips = src_ips.union(&dst_ips).count();
    if total_unique_ips < cli.min_unique_ips {
        issues.push(format!(
            "Too few unique IPs: {} (minimum: {})",
            total_unique_ips, cli.min_unique_ips
        ));
    }

    if !stats.has_ip_layer {
        issues.push("No IP layer packets found - cannot be replayed".to_string());
    }

    if stats.unique_ip_pairs == 1 && packet_count > 100 {
        issues.push("Single IP pair - may produce monotonous traffic".to_string());
    }

    let non_ip_ratio = stats.non_ip_packets as f64 / packet_count.max(1) as f64;
    if non_ip_ratio > 0.9 {
        issues.push(format!(
            "High non-IP ratio: {:.1}% - limited replay value",
            non_ip_ratio * 100.0
        ));
    }

    let malformed_ratio = stats.malformed_packets as f64 / packet_count.max(1) as f64;
    if malformed_ratio > 0.1 {
        issues.push(format!(
            "High malformed packet ratio: {:.1}%",
            malformed_ratio * 100.0
        ));
    }

    let valid = issues.is_empty();

    Ok(ValidationReport {
        file_path,
        valid,
        issues,
        stats,
    })
}
