pub mod analyze;
pub mod rewrite;

pub use analyze::{
    AnalyzeCli, FlowData, FlowKey, PacketInfo, SuricataAlert, correlate_alerts_with_flows,
    parse_suricata_alerts, run_from_args, run_with_cli,
};

pub use rewrite::{RewriteCli, run as run_rewrite};

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    analyze::run_from_args(args)
}
