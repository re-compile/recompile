use anyhow::{Context, Result};
use clap::{Arg, Command};
use std::fs;
use std::path::PathBuf;
use vm_launcher::{launch_qemu_and_run, Manifest};

fn main() -> Result<()> {
    env_logger::init();
    let matches = Command::new("re")
        .about("re:compile orchestrator")
        .arg(Arg::new("binary").required(true))
        .arg(Arg::new("manifest").long("manifest").value_name("PATH").required(false))
        .arg(Arg::new("args").num_args(0..).trailing_var_arg(true))
        .get_matches();

    let bin: PathBuf = matches.get_one::<String>("binary").unwrap().into();
    let manifest_cli: Option<&String> = matches.get_one::<String>("manifest");
    let mut candidates = Vec::new();
    if let Some(m) = manifest_cli { candidates.push(PathBuf::from(m)); }
    candidates.push(bin.parent().unwrap_or_else(|| std::path::Path::new(".")).join(".re/manifest.json"));
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
    Ok(())
}



