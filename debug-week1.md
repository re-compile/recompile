re:compile — Week‑1 macOS bring‑up debug notes

1) Where QEMU command is built
- File: recompile/vm-launcher/src/lib.rs
- Function: launch_qemu_and_run
- Excerpt (serial, 9p, seed):

```60:92:recompile/vm-launcher/src/lib.rs
cmd.arg("-nographic")
    .arg("-serial").arg("file:build/.re/console.log")
    .arg("-m").arg("2048")
    .arg("-device").arg("virtio-serial-pci")
    .arg("-chardev").arg("file,id=rechan,path=./build/re-findings.log,append=on")
    .arg("-device").arg("virtserialport,chardev=rechan,name=re.findings")
    .arg("-fsdev").arg(format!("local,id=fsdev0,path={},security_model=none,readonly=off", manifest.cwd))
    .arg("-device").arg("virtio-9p-pci,fsdev=fsdev0,mount_tag=host");
if seed_iso.exists() {
    cmd.arg("-device").arg("virtio-scsi-pci,id=scsi0")
        .arg("-drive").arg(format!("id=seed,file={},if=none,format=raw,readonly=on", seed_iso.display()))
        .arg("-device").arg("scsi-cd,drive=seed");
}
```

- UEFI + disk setup:
```53:71:recompile/vm-launcher/src/lib.rs
let uefi_code = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd";
let uefi_vars_src = "/opt/homebrew/share/qemu/edk2-aarch64-vars.fd";
let uefi_vars_dst = Path::new("runtime/vm/uefi_vars.fd");
// overlay disk
let rootfs_overlay = Path::new("runtime/vm/ubuntu-arm64.qcow2");
let rootfs_base = Path::new("runtime/vm/rootfs.img");
```

- The launcher overwrites build/.re/qemu.cmd every run (for debugging).
- The overlay ubuntu-arm64.qcow2 is persistent; cloud-init NoCloud cache inside is expected.

2) Virtio‑serial findings path
- Guest port name: re.findings → guest sees /dev/virtio-ports/re.findings
- Host collector: same function launch_qemu_and_run scans build/re-findings.log for lines containing "RE:FINDING:" and mirrors the JSON to build/.re/last_finding.json
- Prefix detection: substring search for "RE:FINDING:" (not anchored)

3) Seed ISO builder
- Script: recompile/scripts/make-seed.sh
- Writes runtime/vm/seed/user-data and meta-data, then builds runtime/vm/seed.iso (mkisofs label: cidata)
- No other script rewrites runtime/vm/user-data or meta-data; if you manually created them, they aren’t used by make seed (the ISO is built from runtime/vm/seed/*)

4) Manifest summary (example)
- File: recompile/build/.re/manifest.json
- cwd points at repo root; 9p shares that at /host inside the guest

```1:18:recompile/build/.re/manifest.json
{
  "argv": ["memcpy_overflow"],
  "binary": "/…/recompile/build/examples/memcpy_overflow",
  "cwd": "/…/recompile",
  "dsos": ["/usr/lib/libSystem.B.dylib"],
  "env": {"RE_FRAMEPTR": "1"},
  "policy": {"ringbuf_mb": 16, "stack_depth": 64}
}
```

5) Agent status (Week‑1)
- The Rust agent is not yet running in-guest; we simulate a finding via cloud-init echo to /dev/virtio-ports/re.findings. Host captures to build/re-findings.log and mirrors to build/.re/last_finding.json.

6) What to verify right now
- QEMU command: cat build/.re/qemu.cmd (copy/paste to run manually if needed)
- Console log: head/tail build/.re/console.log (if missing, guest didn’t produce console output)
- Findings log: tail -n +1 build/re-findings.log
- Last finding: cat build/.re/last_finding.json | jq .

7) Common causes of "no findings" and fixes
- Seed ISO not detected by cloud-init:
  - Ensure ISO has files at root named exactly: user-data and meta-data
  - Volume label typically must be CIDATA (upper) for NoCloud; we currently use cidata (lower). If needed, switch mkisofs label to CIDATA.
  - Ensure seed is attached as a cdrom device; we attach via virtio-scsi as scsi-cd.
- UEFI VARS not writable:
  - runtime/vm/uefi_vars.fd must be a copy of the template, not the template path itself.
- Disk not writable:
  - We now use an overlay ubuntu-arm64.qcow2; ensure it exists (scripts/fetch-ubuntu-arm64.sh creates it).
- Virtio-serial not ready:
  - cloud-init should modprobe virtio_console or load via /etc/modules-load.d; see first-boot script in week1-macos-fix.md.

8) Next incremental changes if still stuck
- Switch seed label to CIDATA and build ISO with files at ISO root (we can update make-seed.sh accordingly).
- Add -device virtio-net-pci,netdev=n0 -netdev user,id=n0 to enable apt reliably for bpftool.
- Print a RE:READY line from cloud-init to both console and re.findings for bring-up confirmation.

9) Paths quick reference
- Launcher: recompile/vm-launcher/src/lib.rs
- Seed builder: recompile/scripts/make-seed.sh
- Cloud image/overlay: runtime/vm/rootfs.img, runtime/vm/ubuntu-arm64.qcow2
- Seed ISO: runtime/vm/seed.iso
- Collected logs: build/.re/qemu.cmd, build/.re/console.log, build/re-findings.log, build/.re/last_finding.json
