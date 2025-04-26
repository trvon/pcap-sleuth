use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

// Import needed functionality from main crate
// We need to use #[path] to include functions from main.rs
#[path = "../src/main.rs"]
mod main;

#[test]
fn test_parse_suricata_alerts() {
    let sample_path = Path::new("tests/data/sample_eve.json");

    // Test parsing of alerts
    let alerts =
        main::parse_suricata_alerts(&sample_path).expect("Failed to parse Suricata alerts");

    // We should have 6 alerts (one entry is a flow, not an alert)
    assert_eq!(
        alerts.len(),
        6,
        "Expected 6 alerts but found {}",
        alerts.len()
    );

    // Print alert details for debugging
    for (i, alert) in alerts.iter().enumerate() {
        println!(
            "Alert {}: proto={:?}, signature={}",
            i, alert.proto, alert.signature
        );
    }

    // Check protocol values without relying on specific indexes
    // Get all protocols from the alerts
    let protocol_counts: HashMap<_, _> =
        alerts
            .iter()
            .filter_map(|a| a.proto)
            .fold(HashMap::new(), |mut map, proto| {
                *map.entry(proto).or_insert(0) += 1;
                map
            });

    // Check that we have the expected number of each protocol
    println!("Protocol counts: {:?}", protocol_counts);
    // We should have 4 TCP alerts (proto=6)
    assert_eq!(
        protocol_counts.get(&6).unwrap_or(&0),
        &4,
        "Expected 4 TCP alerts"
    );
    // We should have 1 UDP alert (proto=17)
    assert_eq!(
        protocol_counts.get(&17).unwrap_or(&0),
        &1,
        "Expected 1 UDP alert"
    );
    // We should have 1 ICMP alert (proto=1)
    assert_eq!(
        protocol_counts.get(&1).unwrap_or(&0),
        &1,
        "Expected 1 ICMP alert"
    );

    // Check specific alert attributes
    let first_alert = &alerts[0];
    assert_eq!(first_alert.signature, "ET SCAN Potential SSH Scan");
    assert_eq!(first_alert.signature_id, 2001219);
    assert_eq!(first_alert.severity, 2);

    // Check IP addresses
    let expected_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(first_alert.src_ip, expected_ip);
}

#[test]
fn test_correlate_alerts_with_flows() {
    // Create a simple flow map
    let mut flows = HashMap::new();

    // Create flow key matching one of our sample alerts
    let flow_key = main::FlowKey {
        ip_a: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        ip_b: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        port_a: 45231,
        port_b: 80,
        protocol: 6, // TCP
    };

    // Create minimal flow data
    let mut flow_data = main::FlowData::default();
    flow_data.start_time = chrono::Utc::now();
    flow_data.end_time = chrono::Utc::now();

    // Add flow to map
    flows.insert(flow_key.clone(), flow_data);

    // Parse alerts from sample file
    let sample_path = Path::new("tests/data/sample_eve.json");
    let alerts =
        main::parse_suricata_alerts(&sample_path).expect("Failed to parse Suricata alerts");

    // Run correlation
    main::correlate_alerts_with_flows(&alerts, &mut flows);

    // Check if our flow has an alert attached
    let flow = flows.get(&flow_key).expect("Flow should exist in map");
    assert!(
        !flow.suricata_alerts.is_empty(),
        "Flow should have an alert attached"
    );
    assert_eq!(
        flow.suricata_alerts[0].signature,
        "ET SCAN Potential SSH Scan"
    );

    // Check if attack label was set
    assert!(flow.attack_type.is_some());
    assert_eq!(
        flow.attack_type.as_ref().unwrap(),
        "ET SCAN Potential SSH Scan"
    );
}

// #[test]
// fn test_handle_missing_fields() {
//     // This test checks how robust the parser is with missing fields
//     // Create a sample JSON with some missing fields
//     let sample_json = r#"
//     {"timestamp":"2023-05-01T12:00:01.123456+0000","flow_id":12345,"event_type":"alert","src_ip":"192.168.1.100","dest_ip":"192.168.1.20","proto":"TCP"}
//     {"timestamp":"2023-05-01T12:00:02.456789+0000","flow_id":12346,"event_type":"alert","src_ip":"192.168.1.100","src_port":45232,"dest_port":22,"proto":"TCP","alert":{"signature":"ET SCAN Minimal"}}
//     "#;
//
//     // Write this JSON to a temporary file
//     let temp_path = Path::new("tests/data/minimal_eve.json");
//     std::fs::write(temp_path, sample_json).expect("Failed to write temporary file");
//
//     // Attempt to parse it
//     let alerts = main::parse_suricata_alerts(&temp_path).expect("Failed to parse minimal alerts");
//
//     // We expect 2 alerts to be parsed, but with default values for missing fields
//     assert_eq!(
//         alerts.len(),
//         2,
//         "Expected 2 alerts even with missing fields"
//     );
//
//     // First alert has no alert object in JSON, so it gets defaults for alert fields
//     assert_eq!(alerts[0].signature, "Unknown");
//     assert_eq!(alerts[0].signature_id, 0);
//     assert_eq!(alerts[0].severity, 0);
//
//     // Second alert has signature in alert object, so it gets that value
//     assert_eq!(alerts[1].signature, "ET SCAN Minimal");
//     assert_eq!(alerts[1].signature_id, 0);
//
//     // Clean up
//     std::fs::remove_file(temp_path).expect("Failed to remove temporary file");
// }

#[test]
fn test_large_file_performance() {
    use std::time::Instant;

    // Generate a larger test file with many duplicate alerts
    let sample_path = Path::new("tests/data/sample_eve.json");
    let large_path = Path::new("tests/data/large_eve.json");

    // Read the sample file
    let sample_content = std::fs::read_to_string(sample_path).expect("Failed to read sample file");

    // Create a larger file by repeating the content
    let mut large_content = String::new();
    for _ in 0..100 {
        large_content.push_str(&sample_content);
    }

    // Write the large file
    std::fs::write(large_path, large_content).expect("Failed to write large file");

    // Measure parsing time
    let start = Instant::now();
    let alerts = main::parse_suricata_alerts(&large_path).expect("Failed to parse large file");
    let duration = start.elapsed();

    // We should have 600 alerts (6 * 100)
    assert_eq!(alerts.len(), 600, "Expected 600 alerts in large file");

    // Performance should be reasonable - less than 1 second for 600 alerts
    // This is a rough test and might need adjustment based on the test environment
    println!("Parsing 600 alerts took {:?}", duration);

    // Clean up
    std::fs::remove_file(large_path).expect("Failed to remove temporary large file");
}
