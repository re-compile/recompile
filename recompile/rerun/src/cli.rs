//! CLI command handlers

use anyhow::Result;
use clap::ArgMatches;
use re_crashpack::EscalationPlan as FindingEscalationPlan;
use re_escalate::{EscalationConfig, EscalationRunner, Finding};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

use crate::native::run_native;
use crate::summary::{print_findings_summary, read_findings};

#[derive(Deserialize)]
struct NativeRunMetadata {
    binary_path: String,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(rename = "args")]
    _args: Vec<String>,
}

/// Handle the 'run' command
pub fn handle_run_command(matches: &ArgMatches) -> Result<()> {
    let binary = matches.get_one::<String>("binary").unwrap();
    let binary_path = PathBuf::from(binary);

    let vm_mode = matches.get_flag("vm");
    let native_mode = !vm_mode;
    let escalate_mode = matches.get_one::<String>("escalate").unwrap();
    let output_dir = matches
        .get_one::<String>("output")
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| PathBuf::from("build/crashpack"));
    let symbolizer_tool = matches.get_one::<String>("symbolizer").unwrap();
    let args: Vec<String> = matches
        .get_many::<String>("args")
        .map(|args| args.map(|s| s.to_string()).collect())
        .unwrap_or_default();

    println!("RECC Sentinel v0.1.0");
    println!("Analyzing binary: {}", binary_path.display());
    println!(
        "Mode: {}",
        if native_mode {
            "native"
        } else {
            "VM (deferred)"
        }
    );
    println!("Escalation: {}", escalate_mode);
    println!("Symbolizer: {}", symbolizer_tool);
    println!("Output: {}", output_dir.display());

    if vm_mode {
        return Err(anyhow::anyhow!(
            "VM mode is deferred and not part of the supported workflow.\n\
             Use `re run --native <binary>` on Linux, or run inside the documented Docker-native environment."
        ));
    }

    run_native(
        &binary_path,
        &output_dir,
        escalate_mode,
        symbolizer_tool,
        &args,
    )?;

    println!(
        "Analysis completed. Results saved to: {}",
        output_dir.display()
    );
    Ok(())
}

/// Handle the 'escalate' command
pub fn handle_escalate_command(matches: &ArgMatches) -> Result<()> {
    let crashpack_path = matches.get_one::<String>("crashpack").unwrap();
    let tool = matches.get_one::<String>("tool").unwrap();
    let crashpack_dir = PathBuf::from(crashpack_path);
    let findings_path = crashpack_dir.join("findings.json");

    println!("Running escalation analysis on: {}", crashpack_path);
    println!("Tool: {}", tool);

    if !findings_path.exists() {
        return Err(anyhow::anyhow!(
            "No findings.json found in {}",
            crashpack_dir.display()
        ));
    }

    let findings = load_findings(&findings_path)?;
    if findings.is_empty() {
        println!("No findings to escalate.");
        return Ok(());
    }

    let analysis = load_analysis_metadata(&crashpack_dir)?;
    let mut config = EscalationConfig::default();
    config.output_dir = crashpack_dir.join("escalations").display().to_string();
    config.binary_path = Some(analysis.binary_path.clone());
    config.source_file = analysis.source_path.clone();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let mut runner = EscalationRunner::new(config);
        for mut finding in findings {
            if tool != "all" {
                let mut plan = finding.escalation.unwrap_or(FindingEscalationPlan {
                    tool: tool.to_string(),
                    reason: "manual_override".to_string(),
                    estimated_cost: "unknown".to_string(),
                    cooldown_ms: 0,
                });
                plan.tool = tool.to_string();
                finding.escalation = Some(plan);
            }

            if let Some(plan) = &finding.escalation {
                println!("Escalating finding {} with tool {}", finding.id, plan.tool);
                let result = runner.escalate(&finding).await?;
                if result.success {
                    println!(
                        "✓ Escalation successful: {} ({}ms)",
                        result.tool, result.duration_ms
                    );
                    if let Some(output_path) = result.output_path {
                        println!("  Output: {}", output_path);
                    }
                } else {
                    println!(
                        "✗ Escalation failed: {} ({}ms)",
                        result.tool, result.duration_ms
                    );
                    if let Some(error) = result.error {
                        println!("  Error: {}", error);
                    }
                }
            } else {
                println!("Skipping {}: no escalation plan", finding.id);
            }
        }

        Ok::<(), anyhow::Error>(())
    })?;

    println!("Escalation analysis completed.");
    Ok(())
}

/// Handle the 'crashpack' command
pub fn handle_crashpack_command(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("open", sub_matches)) => {
            let path = sub_matches.get_one::<String>("path").unwrap();
            open_crashpack(path)?;
        }
        Some(("validate", sub_matches)) => {
            let path = sub_matches.get_one::<String>("path").unwrap();
            validate_crashpack(path)?;
        }
        _ => {
            eprintln!("Use 're crashpack open <path>' or 're crashpack validate <path>'");
        }
    }
    Ok(())
}

fn load_findings(path: &PathBuf) -> Result<Vec<Finding>> {
    let content = fs::read_to_string(path)?;
    match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(serde_json::Value::Array(_)) => serde_json::from_str::<Vec<Finding>>(&content)
            .map_err(|error| anyhow::anyhow!("Failed to parse {}: {}", path.display(), error)),
        Ok(_) => Err(anyhow::anyhow!(
            "{} must contain a JSON array of findings",
            path.display()
        )),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to parse {}: {}",
            path.display(),
            error
        )),
    }
}

fn load_analysis_metadata(crashpack_dir: &PathBuf) -> Result<NativeRunMetadata> {
    let path = crashpack_dir.join("analysis.json");
    let content = fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("Failed to read {}: {}", path.display(), error))?;
    serde_json::from_str::<NativeRunMetadata>(&content)
        .map_err(|error| anyhow::anyhow!("Failed to parse {}: {}", path.display(), error))
}

/// Open and display crashpack summary
fn open_crashpack(path: &str) -> Result<()> {
    let crashpack_path = PathBuf::from(path);

    if !crashpack_path.exists() {
        return Err(anyhow::anyhow!("Crashpack not found: {}", path));
    }

    println!("Crashpack: {}", crashpack_path.display());

    // Check for manifest
    let manifest_path = crashpack_path.join("manifest.json");
    if manifest_path.exists() {
        let manifest_content = fs::read_to_string(&manifest_path)?;
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;
        println!("Manifest:");
        println!(
            "  Schema:   {}",
            manifest
                .get("schema_version")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
        );
        println!(
            "  Findings: {}",
            manifest
                .get("total_findings")
                .and_then(|value| value.as_u64())
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!(
            "  Created:  {}",
            manifest
                .get("created_by")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
        );
    }

    // Check for findings
    let findings_path = crashpack_path.join("findings.json");
    if findings_path.exists() {
        println!("\nFindings:");
        let findings = read_findings(&findings_path)?;
        print_findings_summary(&findings);
    }

    // Check for harnesses
    let harnesses_dir = crashpack_path.join("harnesses");
    if harnesses_dir.exists() {
        let harness_files: Vec<_> = fs::read_dir(&harnesses_dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();

        if !harness_files.is_empty() {
            println!("\nGenerated harnesses:");
            for harness in harness_files {
                println!("  {}", harness);
            }
        }
    }

    Ok(())
}

/// Validate crashpack structure and contents
fn validate_crashpack(path: &str) -> Result<()> {
    let crashpack_path = PathBuf::from(path);

    if !crashpack_path.exists() {
        return Err(anyhow::anyhow!("Crashpack not found: {}", path));
    }

    println!("Validating crashpack: {}", crashpack_path.display());

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Check required files
    let required_files = ["manifest.json", "findings.json", "console.log"];
    for file in &required_files {
        let file_path = crashpack_path.join(file);
        if !file_path.exists() {
            errors.push(format!("Missing required file: {}", file));
        }
    }

    // Check manifest structure
    let manifest_path = crashpack_path.join("manifest.json");
    if manifest_path.exists() {
        match fs::read_to_string(&manifest_path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(manifest) => {
                    if let Some(tool_version) = manifest
                        .get("recc_version")
                        .or_else(|| manifest.get("tool_version"))
                    {
                        println!("Tool version: {}", tool_version);
                    } else {
                        warnings.push("Manifest missing recc_version");
                    }

                    if let Some(schema_version) = manifest.get("schema_version") {
                        println!("Schema version: {}", schema_version);
                    } else {
                        warnings.push("Manifest missing schema_version");
                    }
                }
                Err(e) => {
                    errors.push(format!("Invalid manifest.json: {}", e));
                }
            },
            Err(e) => {
                errors.push(format!("Cannot read manifest.json: {}", e));
            }
        }
    }

    // Check findings structure
    let findings_path = crashpack_path.join("findings.json");
    if findings_path.exists() {
        match fs::read_to_string(&findings_path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(findings) => {
                    if findings.is_array() {
                        println!("Findings: {} entries", findings.as_array().unwrap().len());
                    } else {
                        errors.push("findings.json must be a JSON array".to_string());
                    }
                }
                Err(e) => {
                    errors.push(format!("Invalid findings.json: {}", e));
                }
            },
            Err(e) => {
                errors.push(format!("Cannot read findings.json: {}", e));
            }
        }
    }

    // Check harnesses directory
    let harnesses_dir = crashpack_path.join("harnesses");
    if harnesses_dir.exists() {
        let harness_count = fs::read_dir(&harnesses_dir)?
            .filter(|entry| {
                if let Ok(entry) = entry {
                    entry.file_name().to_string_lossy().ends_with(".c")
                } else {
                    false
                }
            })
            .count();

        if harness_count > 0 {
            println!("Harnesses: {} generated", harness_count);
        }
    }

    // Report results
    if errors.is_empty() && warnings.is_empty() {
        println!("✅ Crashpack validation passed");
    } else {
        if !errors.is_empty() {
            println!("❌ Validation errors:");
            for error in errors {
                println!("  {}", error);
            }
        }

        if !warnings.is_empty() {
            println!("⚠️  Validation warnings:");
            for warning in warnings {
                println!("  {}", warning);
            }
        }
    }

    Ok(())
}
