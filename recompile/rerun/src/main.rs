use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command};
use std::fs;
use std::path::PathBuf;
use vm_launcher::{launch_qemu_and_run, Manifest};

mod cli;
mod native;
mod vm;

use cli::*;

fn main() -> Result<()> {
    env_logger::init();
    
    let matches = Command::new("re")
        .about("RECC Sentinel - eBPF-driven compiler companion for C/C++ binaries")
        .version("0.1.0")
        .subcommand(
            Command::new("run")
                .about("Run binary analysis with eBPF monitoring")
                .arg(Arg::new("binary")
                    .help("Binary to analyze")
                    .required(true))
                .arg(Arg::new("manifest")
                    .long("manifest")
                    .value_name("PATH")
                    .help("Path to manifest.json"))
                .arg(Arg::new("native")
                    .long("native")
                    .action(ArgAction::SetTrue)
                    .help("Run in native mode (Linux only, requires CAP_BPF)"))
                .arg(Arg::new("escalate")
                    .long("escalate")
                    .value_name("MODE")
                    .default_value("auto")
                    .help("Escalation mode: auto (on low confidence), always, never"))
                .arg(Arg::new("output")
                    .long("output")
                    .short('o')
                    .value_name("PATH")
                    .help("Output directory for crashpack"))
                .arg(Arg::new("symbolizer")
                    .long("symbolizer")
                    .value_name("TOOL")
                    .default_value("llvm")
                    .help("Symbolization tool to use"))
                .arg(Arg::new("args")
                    .help("Arguments to pass to the binary")
                    .num_args(0..)
                    .trailing_var_arg(true))
        )
        .subcommand(
            Command::new("escalate")
                .about("Run escalation analysis on existing crashpack")
                .arg(Arg::new("crashpack")
                    .help("Path to crashpack directory")
                    .required(true))
                .arg(Arg::new("tool")
                    .long("tool")
                    .value_name("TOOL")
                    .default_value("all")
                    .help("Escalation tool to use"))
        )
        .subcommand(
            Command::new("crashpack")
                .about("Crashpack operations")
                .subcommand(
                    Command::new("open")
                        .about("Open and view crashpack summary")
                        .arg(Arg::new("path")
                            .help("Path to crashpack directory")
                            .required(true))
                )
                .subcommand(
                    Command::new("validate")
                        .about("Validate crashpack structure and contents")
                        .arg(Arg::new("path")
                            .help("Path to crashpack directory")
                            .required(true))
                )
        )
        .get_matches();

    match matches.subcommand() {
        Some(("run", sub_matches)) => {
            handle_run_command(sub_matches)?;
        }
        Some(("escalate", sub_matches)) => {
            handle_escalate_command(sub_matches)?;
        }
        Some(("crashpack", sub_matches)) => {
            handle_crashpack_command(sub_matches)?;
        }
        _ => {
            // Fallback to legacy behavior for backward compatibility
            handle_legacy_run(&matches)?;
        }
    }

    Ok(())
}

fn handle_legacy_run(matches: &clap::ArgMatches) -> Result<()> {
    let binary = matches.get_one::<String>("binary");
    if let Some(bin) = binary {
        let bin_path: PathBuf = bin.into();
        let manifest_cli: Option<&String> = matches.get_one::<String>("manifest");
        let mut candidates = Vec::new();
        if let Some(m) = manifest_cli { candidates.push(PathBuf::from(m)); }
        candidates.push(bin_path.parent().unwrap_or_else(|| std::path::Path::new(".")).join(".re/manifest.json"));
        candidates.push(PathBuf::from("build/.re/manifest.json"));

        let found = candidates.into_iter().find(|p| p.exists());
        if let Some(manifest) = found {
            let s = fs::read_to_string(&manifest)?;
            eprintln!("re: using manifest {}", manifest.display());
            let m: Manifest = serde_json::from_str(&s).context("parse manifest")?;
            launch_qemu_and_run(&m)?;
        } else {
            eprintln!("re: manifest not found in default locations; run recc to generate one.");
        }
    } else {
        eprintln!("re: no binary specified. Use 're run <binary>' or see 're --help' for more options.");
    }
    Ok(())
}



