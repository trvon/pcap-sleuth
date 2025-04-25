# pcap-sleuth (Research Tool)

**pcap-sleuth** is a Rust CLI tool to process PCAP/PCAPNG files, extract per-packet and per-flow metrics, label flows via external rules, and export results to CSV and/or JSON.

## Features

- Read `.pcap`/`.pcapng` with the `pcap` crate
- Parse Ethernet/IP/TCP/UDP/ICMP headers via `pnet`
- Group packets into flows (canonical 5-tuple)
- Aggregate flow stats (start/end times, packet/byte counts)
- Apply labels (IP, port, subnet, flow ID) from a CSV rules file
- Export per-packet CSV and per-flow JSON
- Detect common network attacks using heuristic analysis
- Supports flow timeouts to automatically close inactive connections
- Integrates with Suricata IDS by correlating EVE JSON alerts with flows

## Installation

Requires Rust stable (1.86+).

```bash
git clone https://github.com/trvon/pcap-sleuth.git
cd pcap-sleuth
cargo build --release
```

## Usage

```bash
pcap-sleuth \
  -i path/to/file.pcap \
  -o path/to/out \
  [-c] [-j] [-l rules.csv] [-v|-vv|-vvv] [--detect-attacks] [--scan-threshold <NUM>] [--udp-scan-threshold <NUM>] [--config <CONFIG>] [--suricata-alerts <EVE_JSON>]
```

### Arguments

- `-i, --input <PCAP>`       Path to PCAP/PCAPNG file
- `-o, --output-dir <DIR>`   Directory for output files
- `-c, --csv`                Generate per-packet CSV (`<basename>.csv`)
- `-j, --json`               Generate per-flow JSON (`<basename>.json`)
- `-l, --labels <LABELS>`    CSV file with label rules
- `-v, -vv, -vvv`            Increase verbosity (info, debug, trace)
- `--detect-attacks`         Enable heuristic-based attack detection
- `--scan-threshold <NUM>`   Port scan detection threshold (default: 20)
- `--udp-scan-threshold <NUM>` UDP scan detection threshold (default: 15)
- `--config <CONFIG>`        Path to TOML configuration file
- `--suricata-alerts <EVE_JSON>` Path to Suricata EVE JSON alerts file

### Label Rules Format

A CSV (no header) with rows:

```
type,criteria,label
```

- `ip_addr` — match source or destination IP (e.g. `192.168.1.10`)
- `port`    — match source or destination port (e.g. `80`)
- `subnet`  — match IP in CIDR subnet (e.g. `10.0.0.0/24`)
- `flow_id` — exact flow key (e.g. `6-10.0.0.1:1000-10.0.0.2:2000`)

Example `rules.csv`:

```
ip_addr,192.168.1.10,internal
port,22,ssh_traffic
```

## Output Formats

### CSV Columns

| Field          | Description                                        |
|----------------|----------------------------------------------------|
| timestamp      | Packet time (ISO 8601)                             |
| src_ip, dst_ip | Source and destination IP addresses                |
| src_port, dst_port | Source and destination ports                   |
| protocol       | IP protocol number (6=TCP,17=UDP,1=ICMP,...)       |
| length         | Original packet length in bytes                    |
| payload_length | Transport-layer payload length                     |
| tcp_flags      | TCP flags (numeric)                                |
| flow_id        | Canonical 5-tuple ID                               |
| label          | Assigned label (if any)                            |

### JSON Structure

Top-level object keyed by flow ID:

```json
{
  "6-10.0.0.1:1000-10.0.0.2:2000": {
    "start_time": "2025-04-25T20:00:00Z",
    "end_time":   "2025-04-25T20:05:00Z",
    "packet_count": 42,
    "byte_count":   12345,
    "label":        "ssh_traffic",
    "attack_type":  "tcp_syn_scan"
  },
  ...
}
```

### Attack Detection

pcap-sleuth can detect several common types of network scanning and attack behaviors:

- **TCP SYN Scan**: Detects when a host sends TCP SYN packets to multiple ports on a destination without completing connections.
- **TCP Connect Scan**: Detects when a host establishes full TCP connections to multiple ports on a destination.
- **UDP Scan**: Detects when a host sends UDP packets to multiple ports on a destination.
- **SYN Flood**: Detects potential DoS attacks where a host sends TCP SYN packets to a specific service at a high rate.
- **Port Sweep**: Detects when a host accesses the same port across multiple destination IPs, often indicating network reconnaissance or worm activity.
- **Ping Sweep**: Detects when a host sends ICMP Echo Requests (pings) to multiple destination IPs, used for host discovery.
- **Suricata Alerts**: Integrates alerts from Suricata IDS by correlating them with network flows.

Detection is enabled with the `--detect-attacks` flag or via configuration file, and thresholds can be adjusted.

Detection results are included in the JSON output with an `attack_type` field, and flows associated with detected attacks are labeled with `attack:<type>` if no existing label was specified.

### Configuration File

pcap-sleuth supports configuration via a TOML file specified with the `--config` flag. This allows for more flexible configuration of detection parameters and behavior. Here's an example configuration:

```toml
# pcap-sleuth sample configuration file

[detection]
# Global detection enablement (can be overridden with --detect-attacks CLI flag)
enabled = true

# Settings for different detection heuristics
[detection.heuristics]

# TCP SYN scan detection settings
[detection.heuristics.syn_scan]
enabled = true
threshold = 20  # Number of distinct ports accessed to trigger detection

# TCP Connect scan detection settings
[detection.heuristics.connect_scan]
enabled = true
threshold = 20  # Number of distinct ports with established connections

# UDP scan detection settings
[detection.heuristics.udp_scan]
enabled = true
threshold = 15  # Lower threshold for UDP scans as they're often more targeted

# ICMP Ping Sweep detection settings
[detection.heuristics.ping_sweep]
enabled = true
threshold = 10  # Number of distinct destination IPs to trigger detection

# Label generation settings
[detection.labels]
# Format string for attack labels
# Available placeholders: {type} - the detected attack type
attack_format = "attack:{type}"

# Flow timeout and management settings
[flow]
# TCP flow timeout in seconds (default: 300 seconds = 5 minutes)
tcp_timeout_secs = 300

# UDP flow timeout in seconds (default: 180 seconds = 3 minutes)
udp_timeout_secs = 180

# ICMP flow timeout in seconds (default: 60 seconds = 1 minute)
icmp_timeout_secs = 60

# Flow timeout check interval - check for timeouts every N packets (default: 1000)
check_interval = 1000

# Suricata integration settings
[suricata]
# Enable Suricata alert integration
enabled = true

# Format string for Suricata alert labels
# Available placeholders:
#   {signature} - Alert signature name
#   {alert_category} - Alert category
#   {severity} - Alert severity (1-4, with 1 being highest)
#   {signature_id} - Alert signature ID
alert_format = "suricata:{alert_category}:{signature}"
```

#### Configuration Precedence

When determining settings, pcap-sleuth follows this precedence order:

1. Command-line arguments (highest priority)
2. Configuration file settings
3. Default values (lowest priority)

This allows for flexible configuration while still enabling quick overrides via the command line.

### Flow Timeouts

To handle long captures or live analysis, pcap-sleuth implements flow timeout functionality. This automatically "closes" flows that have been inactive for a configurable period, preventing them from staying open indefinitely and consuming memory.

Flow timeouts are configured in the `[flow]` section of the configuration file:

```toml
[flow]
# Close TCP flows after this many seconds of inactivity (default: 300 = 5 minutes)
tcp_timeout_secs = 300

# Close UDP flows after this many seconds of inactivity (default: 180 = 3 minutes)
udp_timeout_secs = 180

# Close ICMP flows after this many seconds of inactivity (default: 60 = 1 minute)
icmp_timeout_secs = 60

# Check for timeouts after processing this many packets (default: 1000)
check_interval = 1000
```

Timed-out flows are still included in the final JSON output and can receive labels just like active flows. However, they are removed from active memory during processing to reduce memory usage.

When a flow times out:

1. It is marked with its last packet's timestamp as the end time
2. It is removed from the active flows collection
3. It is stored separately until final output generation
4. All analysis (attack detection, labeling) is still applied to it

### Suricata Integration

pcap-sleuth can integrate with the Suricata IDS by correlating alerts from Suricata's EVE JSON output with the network flows detected in the PCAP file. This provides enriched context and leverages Suricata's powerful detection capabilities.

To use this feature, run Suricata on your PCAP file first:

```bash
suricata -r input.pcap -l suricata_output
```

Then, provide the Suricata EVE JSON output file to pcap-sleuth:

```bash
pcap-sleuth -i input.pcap -o output_dir -j --suricata-alerts suricata_output/eve.json
```

Suricata integration is configured in the `[suricata]` section of the configuration file:

```toml
[suricata]
# Enable Suricata alert integration
enabled = true

# Format string for Suricata alert labels
# Available placeholders:
#   {signature} - Alert signature name
#   {alert_category} - Alert category
#   {severity} - Alert severity (1-4, with 1 being highest)
#   {signature_id} - Alert signature ID
alert_format = "suricata:{alert_category}:{signature}"
```

When a Suricata alert matches a flow:

1. The alert is attached to the flow in the JSON output
2. If the flow has no existing attack label, it's labeled with the formatted alert string
3. This enhances the flow data with professional IDS detections
4. The correlation is based on the 5-tuple (source IP, destination IP, source port, destination port, protocol)

## Testing

```bash
cargo test
```

## Continuous Integration

CI is configured with GitHub Actions in `.github/workflows/rust.yml`, running `fmt`, `clippy`, `build`, and tests on each push or PR.
