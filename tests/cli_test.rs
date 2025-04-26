use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_basic_cli_functionality() {
    // You'll need to replace this with an actual small test PCAP file path
    let test_pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/test.pcap");

    // Skip test if test PCAP file doesn't exist
    if !test_pcap_path.exists() {
        println!(
            "Skipping CLI test - test PCAP file not found at {:?}",
            test_pcap_path
        );
        return;
    }

    // Create a temp directory for output
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let output_dir = temp_dir.path();

    // Basic run test with CSV output
    let mut cmd = Command::cargo_bin("pcap-sleuth").expect("Failed to find binary");
    cmd.arg("-i")
        .arg(&test_pcap_path)
        .arg("-o")
        .arg(output_dir)
        .arg("-c"); // Use the short flag for CSV output

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Starting pcap-sleuth"))
        .stdout(predicate::str::contains("Wrote CSV output"));

    // Check if output CSV file was created
    let output_files = fs::read_dir(output_dir).expect("Failed to read output directory");
    let has_csv = output_files
        .filter_map(Result::ok)
        .any(|entry| entry.path().extension().map_or(false, |ext| ext == "csv"));

    assert!(has_csv, "CSV output file not found");
}

#[test]
fn test_json_output() {
    let test_pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/test.pcap");

    if !test_pcap_path.exists() {
        println!(
            "Skipping JSON output test - test PCAP file not found at {:?}",
            test_pcap_path
        );
        return;
    }

    let temp_dir = tempdir().expect("Failed to create temp directory");
    let output_dir = temp_dir.path();

    // Test with JSON output
    let mut cmd = Command::cargo_bin("pcap-sleuth").expect("Failed to find binary");
    cmd.arg("-i")
        .arg(&test_pcap_path)
        .arg("-o")
        .arg(output_dir)
        .arg("-j"); // Use the short flag for JSON output

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Wrote JSON output"));

    // Check if output JSON file was created
    let output_files = fs::read_dir(output_dir).expect("Failed to read output directory");
    let has_json = output_files
        .filter_map(Result::ok)
        .any(|entry| entry.path().extension().map_or(false, |ext| ext == "json"));

    assert!(has_json, "JSON output file not found");

    // TODO: Optionally check JSON structure if needed
}

#[test]
fn test_labels() {
    let test_pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/test.pcap");

    if !test_pcap_path.exists() {
        println!(
            "Skipping labels test - test PCAP file not found at {:?}",
            test_pcap_path
        );
        return;
    }

    let temp_dir = tempdir().expect("Failed to create temp directory");
    let output_dir = temp_dir.path();

    // Create a temporary labels file
    let labels_file = temp_dir.path().join("test_labels.csv");
    {
        let mut file = fs::File::create(&labels_file).expect("Failed to create labels file");
        writeln!(file, "ip_addr,192.168.1.1,test_device").expect("Failed to write to labels file");
        writeln!(file, "port,80,http_traffic").expect("Failed to write to labels file");
    }

    // Test with labels
    let mut cmd = Command::cargo_bin("pcap-sleuth").expect("Failed to find binary");
    cmd.arg("-i")
        .arg(&test_pcap_path)
        .arg("-o")
        .arg(output_dir)
        .arg("-j")
        .arg("-l")
        .arg(&labels_file);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Loaded 2 label rules"));

    // Further verification could include checking if labels were applied in output
}
