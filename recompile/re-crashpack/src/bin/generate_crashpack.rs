//! Crashpack generator binary
//!
//! Generates crashpack artifacts from an existing findings file.

use anyhow::{anyhow, Result};
use re_crashpack::*;
use std::fs;
use std::path::{Path, PathBuf};

struct Args {
    findings_file: PathBuf,
    output_dir: PathBuf,
    console_log: Option<PathBuf>,
    binaries: Vec<PathBuf>,
    inputs: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = parse_args()?;

    println!(
        "Generating crashpack from {} to {}",
        args.findings_file.display(),
        args.output_dir.display()
    );

    let findings = parse_findings(&args.findings_file)?;
    if findings.is_empty() {
        return Err(anyhow!("no findings were found in the input file"));
    }

    let mut crashpack = Crashpack::new();
    for finding in findings {
        crashpack.add_finding(finding);
    }

    for binary in &args.binaries {
        crashpack.add_binary(BinaryInfo::analyze(binary)?);
    }

    crashpack.generate(&args.output_dir)?;

    if let Some(console_log_path) = args.console_log {
        copy_file(&console_log_path, &args.output_dir.join("console.log"))?;
    }

    if !args.inputs.is_empty() {
        let inputs_dir = args.output_dir.join("inputs");
        fs::create_dir_all(&inputs_dir)?;
        for input in &args.inputs {
            let dest = inputs_dir.join(
                input
                    .file_name()
                    .ok_or_else(|| anyhow!("input path has no file name: {}", input.display()))?,
            );
            copy_file(input, &dest)?;
        }
    }

    println!(
        "Crashpack generated successfully with {} findings",
        crashpack.findings.len()
    );
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut it = std::env::args().skip(1);
    let first = it.next().ok_or_else(|| anyhow!("usage: generate_crashpack <findings_file> <output_dir> [--console-log <path>] [--binary <path> ...] [--input <path> ...]"))?;
    if first == "--help" || first == "-h" {
        print_usage();
        std::process::exit(0);
    }

    let second = it.next().ok_or_else(|| anyhow!("usage: generate_crashpack <findings_file> <output_dir> [--console-log <path>] [--binary <path> ...] [--input <path> ...]"))?;
    let mut args = Args {
        findings_file: PathBuf::from(first),
        output_dir: PathBuf::from(second),
        console_log: None,
        binaries: Vec::new(),
        inputs: Vec::new(),
    };

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--console-log" => {
                let value = it.next().ok_or_else(|| anyhow!("--console-log requires a path"))?;
                args.console_log = Some(PathBuf::from(value));
            }
            "--binary" => {
                let value = it.next().ok_or_else(|| anyhow!("--binary requires a path"))?;
                args.binaries.push(PathBuf::from(value));
            }
            "--input" => {
                let value = it.next().ok_or_else(|| anyhow!("--input requires a path"))?;
                args.inputs.push(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                return Err(anyhow!("unknown argument: {}", other));
            }
        }
    }

    Ok(args)
}

fn print_usage() {
    eprintln!(
        "usage: generate_crashpack <findings_file> <output_dir> [--console-log <path>] [--binary <path> ...] [--input <path> ...]"
    );
}

fn parse_findings(findings_file: &Path) -> Result<Vec<Finding>> {
    let content = fs::read_to_string(findings_file)?;

    if let Ok(json_findings) = serde_json::from_str::<Vec<Finding>>(&content) {
        return Ok(json_findings);
    }

    if let Ok(finding) = serde_json::from_str::<Finding>(&content) {
        return Ok(vec![finding]);
    }

    let mut findings = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let json_part = line
            .strip_prefix("RE:FINDING:")
            .map(str::trim)
            .unwrap_or(line);

        if let Ok(finding) = serde_json::from_str::<Finding>(json_part) {
            findings.push(finding);
        }
    }

    Ok(findings)
}

fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    if !src.exists() {
        return Err(anyhow!("file not found: {}", src.display()));
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}
