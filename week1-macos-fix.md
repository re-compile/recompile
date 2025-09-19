re:compile — macOS Apple Silicon (arm64) VM Bring‑Up & Finding Pipeline

This README gives copy‑pasteable steps to fix the “no findings / empty logs” issue on macOS Apple Silicon by booting a reliable UEFI + Ubuntu ARM64 cloud image under QEMU/HVF, sharing the repo via 9p, generating vmlinux.h inside the guest, and capturing RE:FINDING: lines to the host.

TL;DR
	•	Don’t use direct -kernel boots on mac — use UEFI.
	•	Use arm64 guest with HVF acceleration.
	•	Share workspace via virtio‑9p (not virtiofsd on mac).
	•	Generate runtime/bpf/vmlinux.h inside the guest, then make bpf on host.
	•	Print findings to virtio‑serial (captured to build/re-findings.log) and mirror the last JSON to build/.re/last_finding.json.

⸻

0) Prereqs (Homebrew)

brew install qemu jq zstd llvm coreutils
# Optional for ISO tooling (else use hdiutil):
brew install cdrtools   # provides genisoimage

Firmware (bundled with Homebrew QEMU):

QPREFIX="$(brew --prefix qemu)"
export OVMF_CODE="$QPREFIX/share/qemu/edk2-aarch64-code.fd"
export OVMF_VARS_TEMPLATE="$QPREFIX/share/qemu/edk2-aarch64-vars.fd"


⸻

1) Prepare VM artifacts

From repo root:

mkdir -p runtime/vm && cd runtime/vm

# 1.1 Cloud image (Ubuntu 22.04 ARM64)
curl -L -o jammy-arm64.img \
  https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img

# 1.2 Writable overlay
qemu-img create -f qcow2 -b jammy-arm64.img -F qcow2 ubuntu-arm64.qcow2 8G

# 1.3 UEFI VARS (MUST be a copy of the template)
cp "$OVMF_VARS_TEMPLATE" uefi_vars.fd

1.4 Create cloud‑init seed (NoCloud)

Create runtime/vm/user-data:

#cloud-config
hostname: re-guest
users:
  - name: re
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [sudo]
    shell: /bin/bash
    plain_text_passwd: "re"
    lock_passwd: false
package_update: false
package_upgrade: false

write_files:
  - path: /etc/modules-load.d/re.conf
    permissions: "0644"
    content: |
      virtio_console
      9pnet_virtio
      9p
  - path: /usr/local/bin/re-firstboot.sh
    permissions: "0755"
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      mkdir -p /host || true
      # Mount host via 9p
      mount -t 9p -o trans=virtio,version=9p2000.L host /host || true
      # Install bpftool if available network; ignore failure if offline
      if ! command -v bpftool >/dev/null 2>&1; then
        (apt-get update && apt-get install -y bpftool) || true
      fi
      # Dump BTF header for CO-RE to host tree
      if command -v bpftool >/dev/null 2>&1; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > /host/runtime/bpf/vmlinux.h || true
      fi
      echo "RE:READY: mounted_host=$(mount | grep ' on /host ' | wc -l) vmlinux=$(test -s /host/runtime/bpf/vmlinux.h && echo ok || echo miss)"

runcmd:
  - [ bash, -lc, "/usr/local/bin/re-firstboot.sh" ]

Create runtime/vm/meta-data:

instance-id: iid-re-1
local-hostname: re-guest

Build seed ISO with label CIDATA:

cd runtime/vm
# Option A (mac built-in):
hdiutil makehybrid -o seed.iso -hfs -joliet -iso -default-volume-name CIDATA user-data meta-data
# Option B (cdrtools):
# genisoimage -output seed.iso -volid CIDATA -joliet -rock user-data meta-data


⸻

2) QEMU launch (HVF + UEFI + 9p + virtio‑serial)

Your launcher should produce a command like this (we also write it to build/.re/qemu.cmd for debugging):

mkdir -p build/.re
qemu-system-aarch64 \
  -machine virt,accel=hvf \
  -cpu host -smp 4 -m 2048 \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file=runtime/vm/uefi_vars.fd \
  -drive id=hd0,file=runtime/vm/ubuntu-arm64.qcow2,if=none,format=qcow2 \
  -device virtio-blk-pci,drive=hd0 \
  -device virtio-scsi-pci,id=scsi0 \
  -drive id=seed,file=runtime/vm/seed.iso,if=none,format=raw,readonly=on \
  -device scsi-cd,drive=seed \
  # 9p share of the repo at /host inside the guest
  -fsdev local,id=fsdev0,path="$(pwd)/..",security_model=none,readonly=off \
  -device virtio-9p-pci,fsdev=fsdev0,mount_tag=host \
  # virtio-serial sink for findings
  -device virtio-serial-pci \
  -chardev file,id=rechan,path=./build/re-findings.log,append=on \
  -device virtserialport,chardev=rechan,name=re.findings \
  # console logs to a file for troubleshooting
  -serial file:build/.re/console.log \
  # optional user-mode networking (for apt)
  -device virtio-net-pci,netdev=n0 -netdev user,id=n0

Note: We write findings to the virtio‑serial port named re.findings. The guest agent should open /dev/virtio-ports/re.findings and write lines like RE:FINDING: { ... }.

⸻

3) First boot verification

After starting the VM once, verify provisioning:

# 1) Cloud-init and our first-boot script ran:
tail -n +200 build/.re/console.log | grep -E "cloud-init|RE:READY" -n || true

# 2) The 9p mount and vmlinux.h exist:
ls -lh runtime/bpf/vmlinux.h

If vmlinux.h is present and non-empty, you’re good to build BPF.

⸻

4) Build BPF + run an example

# From repo root
make bpf

# Record a build (mac host just records args)
recc -o build/examples/ovf examples/memcpy_overflow.c

# Run in guest (rerun should do guest-build + exec)
RUST_LOG=info ~/.cargo/bin/cargo run -p rerun -- \
  --manifest build/.re/manifest.json \
  --guest-build \
  --vm-log

Check outputs:

# Stream of findings (virtio-serial sink)
tail -n +1 build/re-findings.log
# Last finding mirrored by host
cat build/.re/last_finding.json | jq .

You should see something like:

RE:FINDING: {"id":"F-heap-overflow-001", "kind":"heap_overflow", ...}


⸻

5) Troubleshooting Cheatsheet

(A) UEFI/seed not detected
	•	Ensure runtime/vm/uefi_vars.fd is a copy of $OVMF_VARS_TEMPLATE (not empty).
	•	Recreate seed ISO with label CIDATA (uppercase) and files at ISO root named exactly user-data and meta-data.
	•	Inspect boot logs:

head -200 build/.re/console.log
grep -n "cloud-init" build/.re/console.log



(B) 9p mount failed
	•	Modules load: virtio_console, 9pnet_virtio, 9p (we add via /etc/modules-load.d/re.conf).
	•	Manually try in guest console/SSH: mount -t 9p -o trans=virtio,version=9p2000.L host /host.

(C) vmlinux.h missing
	•	Guest may lack bpftool. If you enabled networking, run in guest:

sudo apt-get update && sudo apt-get install -y bpftool
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /host/runtime/bpf/vmlinux.h


	•	As a temporary fallback, you can place a pre-generated header that matches the guest kernel into runtime/bpf/vmlinux.h.

(D) No RE:FINDING: lines
	•	Ensure your agent opens /dev/virtio-ports/re.findings and writes RE:FINDING: {json} lines.
	•	Also print to stdout (console) as a fallback; check build/.re/console.log.
	•	Confirm your runner tails build/re-findings.log and mirrors the last JSON to build/.re/last_finding.json.

(E) Still stuck? Add more logging
	•	QEMU: add -d guest_errors and use -serial mon:stdio temporarily for interactive bring‑up.
	•	Runner: dump the generated QEMU command: cat build/.re/qemu.cmd.

⸻

6) One‑shot sanity test

cat > examples/memcpy_overflow.c <<'EOF'
#include <string.h>
#include <stdlib.h>
int main() {
  char *p = (char*)malloc(32);
  char buf[64] = {0};
  memcpy(p, buf, 64); // overflow
  free(p);
  return 0;
}
EOF

recc -o build/examples/ovf examples/memcpy_overflow.c
RUST_LOG=info ~/.cargo/bin/cargo run -p rerun -- --manifest build/.re/manifest.json --guest-build --vm-log

# Expect: build/re-findings.log contains a heap_overflow finding; last_finding.json populated


⸻

7) Notes & Next Steps
	•	This guide is macOS‑specific. On Linux hosts, prefer KVM and you can use virtiofsd and AF_VSOCK.
	•	After bring‑up, integrate the agent to also read stacks, symbolize in‑guest (llvm-symbolizer bundled or host fallback), and emit the full Finding JSON schema.
	•	Once stable, you can disable networking in the guest and pre‑install bpftool in the rootfs to keep it offline.