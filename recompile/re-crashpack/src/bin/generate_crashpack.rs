//! Crashpack generator binary
//! 
//! Generates complete crashpack artifacts from findings and environment data.

use re_crashpack::*;
use std::path::Path;
use std::fs;
use serde_json;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <findings_file> <output_dir> [console_log]", args[0]);
        eprintln!("  findings_file: Path to findings.json or re-findings.log");
        eprintln!("  output_dir: Directory to create crashpack in");
        eprintln!("  console_log: Optional path to console.log");
        std::process::exit(1);
    }

    let findings_file = &args[1];
    let output_dir = &args[2];
    let console_log = args.get(3).map(|s| s.as_str());

    println!("Generating crashpack from {} to {}", findings_file, output_dir);

    // Create crashpack
    let mut crashpack = Crashpack::new();

    // Parse findings
    let findings = parse_findings(findings_file)?;
    for finding in findings {
        crashpack.add_finding(finding);
    }

    // Add binary information
    if let Ok(binary_info) = BinaryInfo::analyze("build/examples/invalid_free") {
        crashpack.add_binary(binary_info);
    }

    // Generate crashpack
    crashpack.generate(Path::new(output_dir))?;

    // Copy console log if provided
    if let Some(console_log_path) = console_log {
        if Path::new(console_log_path).exists() {
            let dest_console = Path::new(output_dir).join("console.log");
            fs::copy(console_log_path, dest_console)?;
            println!("Copied console log to crashpack");
        }
    }

    println!("Crashpack generated successfully with {} findings", crashpack.findings.len());
    Ok(())
}

fn parse_findings(findings_file: &str) -> std::result::Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(findings_file)?;
    let mut findings = Vec::new();

    // Try to parse as JSON array first
    if let Ok(json_findings) = serde_json::from_str::<Vec<Finding>>(&content) {
        return Ok(json_findings);
    }

    // Parse as line-delimited JSON (each line is a separate JSON object)
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        
        // Skip RE:FINDING: prefix if present
        let json_part = if line.starts_with("RE:FINDING: ") {
            &line[12..]
        } else {
            line
        };
        
        if let Ok(finding) = serde_json::from_str::<Finding>(json_part) {
            findings.push(finding);
        }
    }

    Ok(findings)
}
