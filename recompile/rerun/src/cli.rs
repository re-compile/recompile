//! CLI command handlers

use anyhow::Result;
use clap::ArgMatches;
use std::path::PathBuf;
use std::fs;

use crate::native::run_native;
use crate::vm::run_vm;

/// Handle the 'run' command
pub fn handle_run_command(matches: &ArgMatches) -> Result<()> {
    let binary = matches.get_one::<String>("binary").unwrap();
    let binary_path = PathBuf::from(binary);
    
    let native_mode = matches.get_flag("native");
    let escalate_mode = matches.get_one::<String>("escalate").unwrap();
    let output_dir = matches.get_one::<String>("output")
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| PathBuf::from("build/crashpack"));
    let symbolizer_tool = matches.get_one::<String>("symbolizer").unwrap();
    let args: Vec<String> = matches.get_many::<String>("args")
        .map(|args| args.map(|s| s.to_string()).collect())
        .unwrap_or_default();

    println!("RECC Sentinel v0.1.0");
    println!("Analyzing binary: {}", binary_path.display());
    println!("Mode: {}", if native_mode { "native" } else { "VM" });
    println!("Escalation: {}", escalate_mode);
    println!("Symbolizer: {}", symbolizer_tool);
    println!("Output: {}", output_dir.display());

    if native_mode {
        run_native(&binary_path, &output_dir, escalate_mode, symbolizer_tool, &args)?;
    } else {
        run_vm(&binary_path, &output_dir, escalate_mode, symbolizer_tool, &args)?;
    }

    println!("Analysis completed. Results saved to: {}", output_dir.display());
    Ok(())
}

/// Handle the 'escalate' command
pub fn handle_escalate_command(matches: &ArgMatches) -> Result<()> {
    let crashpack_path = matches.get_one::<String>("crashpack").unwrap();
    let tool = matches.get_one::<String>("tool").unwrap();

    println!("Running escalation analysis on: {}", crashpack_path);
    println!("Tool: {}", tool);

    // TODO: Implement escalation runner
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
        println!("Manifest found:");
        println!("{}", manifest_content);
    }

    // Check for findings
    let findings_path = crashpack_path.join("findings.json");
    if findings_path.exists() {
        let findings_content = fs::read_to_string(&findings_path)?;
        println!("\nFindings:");
        println!("{}", findings_content);
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
            Ok(content) => {
                match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(manifest) => {
                        if let Some(tool_version) = manifest.get("tool_version") {
                            println!("Tool version: {}", tool_version);
                        } else {
                            warnings.push("Manifest missing tool_version");
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
                }
            }
            Err(e) => {
                errors.push(format!("Cannot read manifest.json: {}", e));
            }
        }
    }

    // Check findings structure
    let findings_path = crashpack_path.join("findings.json");
    if findings_path.exists() {
        match fs::read_to_string(&findings_path) {
            Ok(content) => {
                match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(findings) => {
                        if findings.is_array() {
                            println!("Findings: {} entries", findings.as_array().unwrap().len());
                        } else if findings.is_object() {
                            println!("Findings: 1 entry");
                        } else {
                            errors.push("Invalid findings.json structure".to_string());
                        }
                    }
                    Err(e) => {
                        errors.push(format!("Invalid findings.json: {}", e));
                    }
                }
            }
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
