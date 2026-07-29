# pcap-sleuth

Rust CLI for exploring PCAP/PCAPNG captures, computing flow statistics, applying labels, and exporting reports.

## Highlights
- Reads PCAP/PCAPNG via `pcap` and decodes Ethernet/IP/TCP/UDP/ICMP headers.
- Builds canonical 5-tuple flows with timing, packet, and byte counters.
- Attaches labels from CSV rules or Suricata EVE JSON alerts.
- Emits per-packet CSV and per-flow JSON artifacts.
- Optional heuristics flag common scan and flood behaviours.

## Install
Requires Rust 1.86 or newer.

```bash
cargo install --path .
```

## Usage
Analyze a capture and emit CSV + JSON:

```bash
pcap-sleuth -i input.pcap -o out --csv --json --labels rules.csv
```

Experimental rewrite pass for normalising captures:

```bash
pcap-sleuth rewrite --input sample.pcapng --manifest manifest.json --dry-run --progress-every 1000000
```

For large-capture benchmarking without emitting a rewritten file:

```bash
pcap-sleuth rewrite --input huge.pcap --dry-run --max-packets 5000000 --progress-every 500000
```

See `sample-config.toml` for advanced tuning, including flow timeouts, attack thresholds, and Suricata integration. Label rules follow the three-column CSV format `type,criteria,label` (types: `ip_addr`, `port`, `subnet`, `flow_id`).

## Development
Run the standard quality gates locally:

```bash
cargo fmt
cargo clippy
cargo test
```

Continuous integration mirrors these checks through `.github/workflows/rust.yml` on every push and pull request.
