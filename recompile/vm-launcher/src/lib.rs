use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmPolicy {
    pub stack_depth: u32,
    pub ringbuf_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub binary: String,
    pub argv: Vec<String>,
    pub env: serde_json::Value,
    pub build_id: String,
    pub dsos: Vec<String>,
    pub cwd: String,
    pub policy: VmPolicy,
}

pub fn launch_qemu_and_run(manifest: &Manifest) -> Result<()> {
    // Week-1: build a QEMU command that boots our VM image and mounts /host via virtio-fs
    let qemu = match detect_qemu() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("vm-launcher: qemu not found. Install it (e.g., 'brew install qemu' on macOS). Printing intended command only.");
            "qemu-system-aarch64".to_string()
        }
    };
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
    let mut cmd = Command::new(qemu);
    cmd.arg("-machine").arg("virt");
    if arch == "aarch64" {
        cmd.arg("-cpu").arg("max");
    }
    // Legacy VM assets. VM mode is deferred and no longer has an active
    // bootstrap script in the primary workflow.
    let kernel = Path::new("runtime/vm/kernel/vmlinuz");
    let initrd = Path::new("runtime/vm/kernel/initrd");
    let rootfs_overlay = Path::new("runtime/vm/ubuntu-arm64.qcow2");
    let rootfs_base = Path::new("runtime/vm/rootfs.img");
    let seed_iso = Path::new("runtime/vm/seed.iso");
    // Acceleration: HVF on macOS/aarch64; else TCG (software) for portability in Week-1
    if cfg!(target_os = "macos") && arch == "aarch64" {
        cmd.arg("-accel").arg("hvf");
    } else {
        cmd.arg("-accel").arg("tcg");
    }

    // Prefer UEFI firmware bundled with Homebrew QEMU; else fallback to direct kernel boot
    let uefi_code = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd";
    let uefi_vars_src = "/opt/homebrew/share/qemu/edk2-aarch64-vars.fd";
    let uefi_vars_dst = Path::new("runtime/vm/uefi_vars.fd");
    if Path::new(uefi_code).exists() {
        if Path::new(uefi_vars_src).exists() && !uefi_vars_dst.exists() {
            let _ = fs::create_dir_all("runtime/vm");
            let _ = fs::copy(uefi_vars_src, uefi_vars_dst);
        }
        cmd.arg("-drive").arg(format!("if=pflash,format=raw,readonly=on,file={}", uefi_code))
            .arg("-drive").arg(format!("if=pflash,format=raw,file={}", uefi_vars_dst.display()))
            .arg("-drive").arg(format!("id=hd0,file={},if=none,format=qcow2", rootfs_overlay.display()))
            .arg("-device").arg("virtio-blk-pci,drive=hd0");
    } else {
        cmd.arg("-kernel").arg(kernel);
        if initrd.exists() { cmd.arg("-initrd").arg(initrd); }
        cmd.arg("-append").arg("console=ttyAMA0 root=/dev/vda1 rw");
        cmd.arg("-drive").arg(format!("id=hd0,file={},if=none,format=raw", rootfs_base.display()))
            .arg("-device").arg("virtio-blk-pci,drive=hd0");
    }

    cmd.arg("-nographic")
        .arg("-serial").arg("file:build/.re/console.log")
        .arg("-m").arg("2048")
        .arg("-device").arg("virtio-serial-pci")
        .arg("-chardev").arg("file,id=rechan,path=./build/re-findings.log,append=on")
        .arg("-device").arg("virtserialport,chardev=rechan,name=re.findings")
        .arg("-fsdev").arg(format!("local,id=fsdev0,path={},security_model=none,readonly=off", manifest.cwd))
        .arg("-device").arg("virtio-9p-pci,fsdev=fsdev0,mount_tag=host");

    if seed_iso.exists() {
        // Attach seed as SCSI CD-ROM with label CIDATA for cloud-init NoCloud
        cmd.arg("-device").arg("virtio-scsi-pci,id=scsi0")
            .arg("-drive").arg(format!("id=seed,file={},if=none,format=raw,readonly=on", seed_iso.display()))
            .arg("-device").arg("scsi-cd,drive=seed");
    }

    // Save the command for debugging
    let _ = fs::create_dir_all("build/.re");
    let cmd_str = format!("{:?}", cmd);
    let _ = fs::write("build/.re/qemu.cmd", cmd_str.as_bytes());

    // Launch QEMU and stream outputs
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Prefer virtio-serial findings log if present
    let log_path = Path::new("./build/re-findings.log");
    for _ in 0..600 { // wait up to ~300s (600 * 500ms)
        if log_path.exists() {
            if let Ok(content) = std::fs::read_to_string(log_path) {
                for line in content.lines() {
                    if let Some(pos) = line.find("RE:FINDING:") {
                        println!("{}", line);
                        let json_part = line[pos + "RE:FINDING:".len()..].trim();
                        let out_dir = std::path::Path::new("build/.re");
                        let _ = std::fs::create_dir_all(out_dir);
                        let out_file = out_dir.join("last_finding.json");
                        let _ = std::fs::write(&out_file, json_part.as_bytes());
                        let _ = child.kill();
                        return Ok(());
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let reader_out = BufReader::new(stdout);
    for line in reader_out.lines() {
        if let Ok(l) = line {
            if let Some(pos) = l.find("RE:FINDING:") {
                println!("{}", l);
                let json_part = l[pos + "RE:FINDING:".len()..].trim();
                let out_dir = std::path::Path::new("build/.re");
                let _ = std::fs::create_dir_all(out_dir);
                let out_file = out_dir.join("last_finding.json");
                let _ = std::fs::write(&out_file, json_part.as_bytes());
                break;
            }
        } else {
            break;
        }
    }
    // Try stderr too (some firmwares print on stderr in -nographic)
    let reader_err = BufReader::new(stderr);
    for line in reader_err.lines() {
        if let Ok(l) = line {
            if let Some(pos) = l.find("RE:FINDING:") {
                println!("{}", l);
                let json_part = l[pos + "RE:FINDING:".len()..].trim();
                let out_dir = std::path::Path::new("build/.re");
                let _ = std::fs::create_dir_all(out_dir);
                let out_file = out_dir.join("last_finding.json");
                let _ = std::fs::write(&out_file, json_part.as_bytes());
                break;
            }
        } else { break; }
    }
    // Best-effort: terminate QEMU after capturing/attempting
    let _ = child.kill();
    Ok(())
}

fn detect_qemu() -> Result<String> {
    if cfg!(target_arch = "aarch64") {
        if let Some(p) = which_in_order(&["/opt/homebrew/bin/qemu-system-aarch64", "qemu-system-aarch64", "qemu-system-arm"]) { return Ok(p); }
    } else {
        if let Some(p) = which_in_order(&["qemu-system-x86_64"]) { return Ok(p); }
    }
    Err(anyhow::anyhow!("qemu not found"))
}

fn which_in_order(candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if Path::new(c).exists() { return Some(c.to_string()); }
        if let Ok(out) = Command::new("/usr/bin/env").arg("which").arg(c).output() {
            if out.status.success() { return Some(String::from_utf8_lossy(&out.stdout).trim().to_string()); }
        }
    }
    None
}

