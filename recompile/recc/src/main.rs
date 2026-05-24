use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

#[derive(Parser, Debug)]
#[command(name = "recc", about = "optional re:compile compile-only wrapper")]
struct Args {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    rest: Vec<OsString>,
    #[arg(long, action = ArgAction::SetTrue, help = "Only write manifest; skip compile")]
    emit_manifest_only: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let cc = detect_underlying_compiler(&args.rest);
    let mut forwarded = args.rest.clone();
    // Remove wrapper-only flags if they sneaked into forwarded due to trailing var arg
    forwarded.retain(|a| a != "--emit-manifest-only");

    // Inject required flags
    forwarded.push(OsString::from("-g"));
    forwarded.push(OsString::from("-fno-omit-frame-pointer"));
    if cfg!(target_os = "linux") {
        forwarded.push(OsString::from("-rdynamic"));
        forwarded.push(OsString::from("-Wl,--export-dynamic"));
    }

    // LLVM pass injection is deferred until the pass ABI and compiler contract are stable.

    let status: ExitStatus = if args.emit_manifest_only {
        // Manifest-only mode: try to infer -o from args, write manifest, return 0
        if let Some(bin) = detect_output_binary(&args.rest) {
            let _ = write_manifest_stub(&bin);
        }
        ExitStatus::from_raw(0)
    } else {
        Command::new(cc)
            .args(&forwarded)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("failed to invoke underlying compiler")?
    };

    // Best-effort manifest emit if we detect a link step with -o <binary>
    if status.success() {
        if let Some(bin) = detect_output_binary(&args.rest) {
            let manifest_path = write_manifest_stub(&bin).ok();
            if let Some(p) = manifest_path {
                eprintln!("recc: wrote manifest stub at {}", p.display());
            }
        }
    }

    std::process::exit(status.code().unwrap_or(1));
}

fn detect_underlying_compiler(args: &[OsString]) -> String {
    let cxx_mode = infer_cxx_mode(args);
    let candidates = if cxx_mode {
        ["clang++", "g++"]
    } else {
        ["clang", "gcc"]
    };

    for candidate in candidates {
        if let Ok(path) = which::which(candidate) {
            return path.to_string_lossy().into_owned();
        }
    }

    if cxx_mode {
        "c++".to_string()
    } else {
        "cc".to_string()
    }
}

fn infer_cxx_mode(args: &[OsString]) -> bool {
    let mut expect_lang = false;

    for arg in args {
        if expect_lang {
            let lang = arg.to_string_lossy();
            if lang.contains("++") {
                return true;
            }
            expect_lang = false;
            continue;
        }

        if arg == "-x" {
            expect_lang = true;
            continue;
        }

        let value = arg.to_string_lossy();
        if value.ends_with(".cc")
            || value.ends_with(".cpp")
            || value.ends_with(".cxx")
            || value.ends_with(".c++")
            || value.ends_with(".C")
        {
            return true;
        }
    }

    false
}

fn detect_output_binary(args: &[OsString]) -> Option<PathBuf> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-o" {
            return it.next().map(PathBuf::from);
        }
    }
    None
}

fn write_manifest_stub(binary: &Path) -> Result<PathBuf> {
    use serde_json::json;
    let cwd = std::env::current_dir()?;
    let build_dir = cwd.join("build/.re");
    std::fs::create_dir_all(&build_dir)?;
    let dsos = detect_dsos(binary).unwrap_or_default();
    let build_id = detect_build_id(binary).unwrap_or_default();
    let manifest = json!({
        "binary": binary.canonicalize().unwrap_or(binary.to_path_buf()).to_string_lossy(),
        "argv": [binary.file_name().and_then(|s| s.to_str()).unwrap_or("a.out")],
        "env": {"RE_FRAMEPTR": "1", "RECC_OPTIONAL": "1"},
        "build_id": build_id,
        "dsos": dsos,
        "cwd": cwd.to_string_lossy(),
        "policy": {"stack_depth": 64, "ringbuf_mb": 16}
    });
    let path = build_dir.join("manifest.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest)?)?;
    Ok(path)
}

fn detect_dsos(binary: &Path) -> Result<Vec<String>> {
    // macOS: otool -L; Linux: ldd
    if cfg!(target_os = "macos") {
        let out = Command::new("otool").arg("-L").arg(binary).output()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let mut libs = Vec::new();
        for (i, line) in s.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Some((path, _rest)) = t.split_once(" (") {
                libs.push(path.trim().to_string());
            }
        }
        Ok(libs)
    } else {
        let out = Command::new("ldd").arg(binary).output()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let mut libs = Vec::new();
        for line in s.lines() {
            if let Some((_left, right)) = line.split_once("=>") {
                let path_part = right.split_whitespace().next().unwrap_or("");
                if path_part.starts_with('/') {
                    libs.push(path_part.to_string());
                }
            } else {
                let path_part = line.split_whitespace().next().unwrap_or("");
                if path_part.starts_with('/') {
                    libs.push(path_part.to_string());
                }
            }
        }
        Ok(libs)
    }
}

fn detect_build_id(binary: &Path) -> Result<String> {
    if !cfg!(target_os = "linux") {
        return Ok(String::new());
    }

    let output = Command::new("readelf").arg("-n").arg(binary).output()?;
    if !output.status.success() {
        return Ok(String::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some((_, build_id)) = line.split_once("Build ID:") {
            return Ok(build_id.trim().to_string());
        }
    }
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os_args(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn detects_c_output_binary() {
        let args = os_args(&["input.c", "-O2", "-o", "build/out"]);
        assert_eq!(
            detect_output_binary(&args),
            Some(PathBuf::from("build/out"))
        );
    }

    #[test]
    fn infers_cxx_from_extension() {
        let args = os_args(&["main.cpp", "-o", "main"]);
        assert!(infer_cxx_mode(&args));
    }

    #[test]
    fn infers_cxx_from_explicit_language() {
        let args = os_args(&["-x", "c++", "main.c", "-o", "main"]);
        assert!(infer_cxx_mode(&args));
    }

    #[test]
    fn c_is_default_language_mode() {
        let args = os_args(&["main.c", "-o", "main"]);
        assert!(!infer_cxx_mode(&args));
    }
}
