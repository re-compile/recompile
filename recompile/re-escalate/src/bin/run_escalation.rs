//! Escalation runner binary
//!
//! Runs escalation on findings from a crashpack

use re_escalate::{EscalationConfig, EscalationRunner, Finding};
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <findings_file> [config_file]", args[0]);
        eprintln!("  findings_file: Path to findings.json");
        eprintln!("  config_file: Optional path to escalation config (defaults to built-in)");
        std::process::exit(1);
    }

    let findings_file = &args[1];
    let config_file = args.get(2);

    println!("Running escalation on findings from: {}", findings_file);

    // Load configuration
    let config = if let Some(config_path) = config_file {
        EscalationConfig::load_from_file(config_path)?
    } else {
        EscalationConfig::default()
    };

    // Create escalation runner
    let mut runner = EscalationRunner::new(config);

    // Load findings
    let findings = load_findings(findings_file)?;
    println!("Loaded {} findings", findings.len());

    // Run escalation on each finding
    for finding in findings {
        if let Some(escalation_plan) = &finding.escalation {
            println!(
                "Escalating finding {} with tool {}",
                finding.id, escalation_plan.tool
            );

            match runner.escalate(&finding).await {
                Ok(result) => {
                    if result.success {
                        println!(
                            "✅ Escalation successful: {} ({}ms)",
                            result.tool, result.duration_ms
                        );
                        if let Some(output_path) = result.output_path {
                            println!("   Output: {}", output_path);
                        }
                    } else {
                        println!(
                            "❌ Escalation failed: {} ({}ms)",
                            result.tool, result.duration_ms
                        );
                        if let Some(error) = result.error {
                            println!("   Error: {}", error);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Escalation error: {}", e);
                }
            }
        } else {
            println!("⚠️  No escalation plan for finding {}", finding.id);
        }
    }

    Ok(())
}

fn load_findings(findings_file: &str) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(findings_file)?;

    // Try to parse as array of findings first
    if let Ok(findings) = serde_json::from_str::<Vec<Finding>>(&content) {
        return Ok(findings);
    }

    // Try to parse as single finding
    if let Ok(finding) = serde_json::from_str::<Finding>(&content) {
        return Ok(vec![finding]);
    }

    // Try to parse as line-delimited JSON
    let mut findings = Vec::new();
    for line in content.lines() {
        if !line.trim().is_empty() {
            if let Ok(finding) = serde_json::from_str::<Finding>(line) {
                findings.push(finding);
            }
        }
    }

    if !findings.is_empty() {
        return Ok(findings);
    }

    Err(format!("Could not parse findings from {}", findings_file).into())
}
