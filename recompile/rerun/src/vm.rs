//! VM mode implementation

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use vm_launcher::{launch_qemu_and_run, Manifest};

/// Run analysis in VM mode
pub fn run_vm(
    binary_path: &PathBuf,
    output_dir: &PathBuf,
    escalate_mode: &str,
    _symbolizer_tool: &str,
    _args: &[String],
) -> Result<()> {
    println!("Running in VM mode...");

    // Create output directory
    std::fs::create_dir_all(output_dir)?;

    // Find manifest
    let manifest = find_manifest(binary_path)?;
    
    // Launch QEMU and run analysis
    launch_qemu_and_run(&manifest)?;

    // Post-process results
    post_process_results(output_dir, escalate_mode)?;

    println!("VM mode analysis completed.");
    Ok(())
}

/// Find manifest file for the binary
fn find_manifest(binary_path: &PathBuf) -> Result<Manifest> {
    let mut candidates = Vec::new();
    
    // Check parent directory for .re/manifest.json
    if let Some(parent) = binary_path.parent() {
        candidates.push(parent.join(".re/manifest.json"));
    }
    
    // Check build directory
    candidates.push(PathBuf::from("build/.re/manifest.json"));
    
    // Check current directory
    candidates.push(PathBuf::from(".re/manifest.json"));

    for manifest_path in candidates {
        if manifest_path.exists() {
            let content = fs::read_to_string(&manifest_path)?;
            println!("Using manifest: {}", manifest_path.display());
            return Ok(serde_json::from_str(&content)
                .context("Failed to parse manifest.json")?);
        }
    }

    Err(anyhow::anyhow!(
        "No manifest found. Run 'recc <binary>' first to generate a manifest."
    ))
}

/// Post-process results after VM analysis
fn post_process_results(output_dir: &PathBuf, escalate_mode: &str) -> Result<()> {
    println!("Post-processing results...");

    // Check if escalation is needed
    if escalate_mode == "always" || escalate_mode == "auto" {
        println!("Running escalation analysis...");
        run_escalation_analysis(output_dir)?;
    }

    // Generate repro harnesses
    generate_repro_harnesses(output_dir)?;

    // Generate crashpack summary
    generate_crashpack_summary(output_dir)?;

    Ok(())
}

/// Run escalation analysis on findings
fn run_escalation_analysis(output_dir: &PathBuf) -> Result<()> {
    // Check if findings exist
    let findings_path = output_dir.join("findings.json");
    if !findings_path.exists() {
        println!("No findings to escalate");
        return Ok(());
    }

    // Run escalation using the re-escalate crate
    println!("Running escalation analysis...");
    
    // Create escalation output directory
    let escalation_dir = output_dir.join("escalation");
    std::fs::create_dir_all(&escalation_dir)?;
    
    // Parse findings and run escalation
    let findings_content = fs::read_to_string(&findings_path)?;
    let findings: Vec<serde_json::Value> = serde_json::from_str(&findings_content)?;
    
    for (i, finding) in findings.iter().enumerate() {
        if let Some(finding_obj) = finding.as_object() {
            println!("Escalating finding {} of {}", i + 1, findings.len());
            
            // Create a temporary finding file for escalation
            let temp_finding_path = escalation_dir.join(format!("finding_{}.json", i));
            fs::write(&temp_finding_path, serde_json::to_string_pretty(finding_obj)?)?;
            
            // Run escalation runner
            let escalation_result = run_escalation_runner(&temp_finding_path, &escalation_dir);
            match escalation_result {
                Ok(output_path) => {
                    println!("✓ Escalation completed: {}", output_path);
                }
                Err(e) => {
                    println!("⚠ Escalation failed for finding {}: {}", i + 1, e);
                }
            }
        }
    }
    
    Ok(())
}

/// Run the escalation runner binary
fn run_escalation_runner(finding_path: &PathBuf, output_dir: &PathBuf) -> Result<String> {
    use std::process::Command;
    
    let output = Command::new("cargo")
        .args(&["run", "--bin", "run_escalation", "--"])
        .arg(finding_path)
        .arg("--output")
        .arg(output_dir)
        .output()?;
    
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Escalation failed: {}", error));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

/// Generate repro harnesses from findings
fn generate_repro_harnesses(output_dir: &PathBuf) -> Result<()> {
    // Check if findings exist
    let findings_path = output_dir.join("findings.json");
    if !findings_path.exists() {
        println!("No findings to generate harnesses for");
        return Ok(());
    }

    println!("Generating repro harnesses...");
    
    // Create harnesses directory
    let harnesses_dir = output_dir.join("harnesses");
    std::fs::create_dir_all(&harnesses_dir)?;
    
    // Parse findings and generate harnesses
    let findings_content = fs::read_to_string(&findings_path)?;
    let findings: Vec<serde_json::Value> = serde_json::from_str(&findings_content)?;
    
    for (i, finding) in findings.iter().enumerate() {
        if let Some(finding_obj) = finding.as_object() {
            println!("Generating harness {} of {}", i + 1, findings.len());
            
            // Create a temporary finding file for harness generation
            let temp_finding_path = harnesses_dir.join(format!("finding_{}.json", i));
            fs::write(&temp_finding_path, serde_json::to_string_pretty(finding_obj)?)?;
            
            // Run harness generator
            let harness_result = run_harness_generator(&temp_finding_path, &harnesses_dir);
            match harness_result {
                Ok(harness_path) => {
                    println!("✓ Harness generated: {}", harness_path);
                }
                Err(e) => {
                    println!("⚠ Harness generation failed for finding {}: {}", i + 1, e);
                }
            }
        }
    }
    
    Ok(())
}

/// Run the harness generator binary
fn run_harness_generator(finding_path: &PathBuf, output_dir: &PathBuf) -> Result<String> {
    use std::process::Command;
    
    let output = Command::new("cargo")
        .args(&["run", "--bin", "generate_harness", "--"])
        .arg(finding_path)
        .arg("--output")
        .arg(output_dir)
        .output()?;
    
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Harness generation failed: {}", error));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

/// Generate crashpack summary
fn generate_crashpack_summary(output_dir: &PathBuf) -> Result<()> {
    let summary_path = output_dir.join("README.md");
    
    let mut summary = String::new();
    summary.push_str("# RECC Crashpack Summary\n\n");
    
    // Add timestamp
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    summary.push_str(&format!("Generated: {}\n\n", timestamp));
    
    // Check for findings
    let findings_path = output_dir.join("findings.json");
    if findings_path.exists() {
        summary.push_str("## Findings\n\n");
        summary.push_str("Findings have been detected and saved to `findings.json`.\n\n");
    } else {
        summary.push_str("## No Findings\n\n");
        summary.push_str("No anomalies were detected during analysis.\n\n");
    }
    
    // Check for harnesses
    let harnesses_dir = output_dir.join("harnesses");
    if harnesses_dir.exists() {
        let harness_count = std::fs::read_dir(&harnesses_dir)?
            .filter(|entry| {
                if let Ok(entry) = entry {
                    entry.file_name().to_string_lossy().ends_with(".c")
                } else {
                    false
                }
            })
            .count();
        
        if harness_count > 0 {
            summary.push_str(&format!("## Repro Harnesses\n\n"));
            summary.push_str(&format!("{} repro harnesses generated in `harnesses/` directory.\n\n", harness_count));
        }
    }
    
    // Add usage instructions
    summary.push_str("## Usage\n\n");
    summary.push_str("To view findings:\n");
    summary.push_str("```bash\n");
    summary.push_str("re crashpack open .\n");
    summary.push_str("```\n\n");
    
    summary.push_str("To run escalation analysis:\n");
    summary.push_str("```bash\n");
    summary.push_str("re escalate .\n");
    summary.push_str("```\n\n");
    
    summary.push_str("To validate crashpack:\n");
    summary.push_str("```bash\n");
    summary.push_str("re crashpack validate .\n");
    summary.push_str("```\n");

    fs::write(&summary_path, summary)?;
    println!("Crashpack summary generated: {}", summary_path.display());

    Ok(())
}
