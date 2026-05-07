use anyhow::Result;
use clap::{Arg, ArgAction, Command, ValueHint};

mod cli;
mod dependencies;
mod issue_groups;
mod native;
mod observation;
mod summary;

use cli::*;

fn main() -> Result<()> {
    env_logger::init();

    let matches = Command::new("re")
        .about("RECC Sentinel - eBPF-driven compiler companion for C/C++ binaries")
        .version("0.1.0")
        .subcommand(
            Command::new("run")
                .about("Run binary analysis with eBPF monitoring")
                .arg(Arg::new("binary").help("Binary to analyze").required(true))
                .arg(
                    Arg::new("manifest")
                        .long("manifest")
                        .value_name("PATH")
                        .help("Path to manifest.json"),
                )
                .arg(
                    Arg::new("native")
                        .long("native")
                        .action(ArgAction::SetTrue)
                        .help("Native mode is now the default on Linux; kept for compatibility"),
                )
                .arg(
                    Arg::new("vm")
                        .long("vm")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("native")
                        .help("VM mode is deferred and not part of the supported workflow"),
                )
                .arg(
                    Arg::new("escalate")
                        .long("escalate")
                        .value_name("MODE")
                        .default_value("auto")
                        .help("Escalation mode: auto (on low confidence), always, never"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("PATH")
                        .help("Output directory for crashpack"),
                )
                .arg(
                    Arg::new("symbolizer")
                        .long("symbolizer")
                        .value_name("TOOL")
                        .default_value("llvm")
                        .help("Symbolization tool to use"),
                )
                .arg(
                    Arg::new("args")
                        .help("Arguments to pass to the binary")
                        .num_args(0..)
                        .trailing_var_arg(true),
                ),
        )
        .subcommand(
            Command::new("observe")
                .about("Observe an already-built native binary and write .re/run-summary.json")
                .arg(
                    Arg::new("binary")
                        .help("Binary to observe")
                        .required(true)
                        .value_hint(ValueHint::FilePath),
                )
                .arg(
                    Arg::new("cwd")
                        .long("cwd")
                        .value_name("PATH")
                        .value_hint(ValueHint::DirPath)
                        .help("Working directory for the target process"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("PATH")
                        .default_value(".re")
                        .value_hint(ValueHint::DirPath)
                        .help("Observation output root"),
                )
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_name("MS")
                        .value_parser(clap::value_parser!(u64))
                        .help("Kill the target if it runs longer than this many milliseconds"),
                )
                .arg(
                    Arg::new("native-only")
                        .long("native-only")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("deep")
                        .help("Run only native observation and skip observe-level escalation"),
                )
                .arg(
                    Arg::new("deep")
                        .long("deep")
                        .action(ArgAction::SetTrue)
                        .help("Run native observation plus whole-binary Valgrind scan and ASan scan when applicable"),
                )
                .arg(
                    Arg::new("args")
                        .help("Arguments to pass to the binary")
                        .num_args(0..)
                        .trailing_var_arg(true),
                ),
        )
        .subcommand(
            Command::new("escalate")
                .about("Run escalation analysis on existing crashpack")
                .arg(
                    Arg::new("crashpack")
                        .help("Path to crashpack directory")
                        .required(true),
                )
                .arg(
                    Arg::new("tool")
                        .long("tool")
                        .value_name("TOOL")
                        .default_value("all")
                        .help("Escalation tool to use"),
                )
                .arg(
                    Arg::new("check-clean")
                        .long("check-clean")
                        .action(ArgAction::SetTrue)
                        .help("Run the selected escalation tool even when the crashpack has no findings"),
                )
                .arg(
                    Arg::new("scan-binary")
                        .long("scan-binary")
                        .action(ArgAction::SetTrue)
                        .help("Run the selected tool against the whole binary instead of per native finding"),
                ),
        )
        .subcommand(
            Command::new("crashpack")
                .about("Crashpack operations")
                .subcommand(
                    Command::new("open")
                        .about("Open and view crashpack summary")
                        .arg(
                            Arg::new("path")
                                .help("Path to crashpack directory")
                                .required(true),
                        ),
                )
                .subcommand(
                    Command::new("validate")
                        .about("Validate crashpack structure and contents")
                        .arg(
                            Arg::new("path")
                                .help("Path to crashpack directory")
                                .required(true),
                        ),
                ),
        )
        .subcommand(
            Command::new("summarize")
                .about("Print a compact agent-readable crashpack summary")
                .arg(
                    Arg::new("crashpack")
                        .help("Path to crashpack directory")
                        .required(true)
                        .value_hint(ValueHint::DirPath),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_name("FORMAT")
                        .default_value("json")
                        .value_parser(["json"])
                        .help("Output format"),
                ),
        )
        .subcommand(
            Command::new("replay")
                .about("Replay the binary and args recorded in a crashpack")
                .arg(
                    Arg::new("crashpack")
                        .help("Path to crashpack directory")
                        .required(true)
                        .value_hint(ValueHint::DirPath),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_name("FORMAT")
                        .default_value("json")
                        .value_parser(["json"])
                        .help("Output format"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("run", sub_matches)) => {
            handle_run_command(sub_matches)?;
        }
        Some(("observe", sub_matches)) => {
            handle_observe_command(sub_matches)?;
        }
        Some(("escalate", sub_matches)) => {
            handle_escalate_command(sub_matches)?;
        }
        Some(("crashpack", sub_matches)) => {
            handle_crashpack_command(sub_matches)?;
        }
        Some(("summarize", sub_matches)) => {
            handle_summarize_command(sub_matches)?;
        }
        Some(("replay", sub_matches)) => {
            handle_replay_command(sub_matches)?;
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
        return Err(anyhow::anyhow!(
            "Legacy manifest-driven VM launch is no longer part of the supported workflow.\n\
             Use `re run --native {}` on Linux, or start the documented Docker-native environment first.",
            bin
        ));
    } else {
        eprintln!(
            "re: no binary specified. Use 're run <binary>' or see 're --help' for more options."
        );
    }
    Ok(())
}
