#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VM_DIR="$ROOT/runtime/vm"
mkdir -p "$VM_DIR/kernel" "$VM_DIR/rootfs"

# Fetch Ubuntu ARM64 cloud image if missing or clearly placeholder/small (<50MB)
NEED_IMG=0
if [ ! -f "$VM_DIR/rootfs.img" ]; then
	NEED_IMG=1
else
	# macOS stat first, then GNU stat
	SIZE=$(stat -f%z "$VM_DIR/rootfs.img" 2>/dev/null || stat -c%s "$VM_DIR/rootfs.img" 2>/dev/null || echo 0)
	if [ "${SIZE:-0}" -lt 52428800 ]; then
		echo "Existing rootfs.img is small (${SIZE} bytes). Fetching Ubuntu cloud image..."
		NEED_IMG=1
	fi
fi

if [ "$NEED_IMG" = "1" ]; then
	"$ROOT/scripts/fetch-ubuntu-arm64.sh"
fi

# Fetch kernel+initrd for aarch64 if missing
if [ ! -f "$VM_DIR/kernel/vmlinuz" ] || [ ! -f "$VM_DIR/kernel/initrd" ]; then
	"$ROOT/scripts/fetch-kernel-arm64.sh"
fi

cat > "$VM_DIR/README.md" <<'EOF'
VM assets
---------

This directory contains the aarch64 Linux kernel with BTF and a glibc-based Ubuntu rootfs image.

Steps (macOS Apple Silicon):
1) brew install qemu curl
2) scripts/build-vm.sh  # downloads Ubuntu jammy ARM64 cloud image
3) Provide a kernel with BTF (we will automate in a later step).

Optional: If you have edk2 firmware, its path is recorded in firmware.path.

llvm-symbolizer will be included inside the VM image in a later step.
EOF

echo "Prepared VM directory at $VM_DIR. Rootfs present: $( [ -f "$VM_DIR/rootfs.img" ] && echo yes || echo no )."


