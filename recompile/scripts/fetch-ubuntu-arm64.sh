#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VM_DIR="$ROOT/runtime/vm"
mkdir -p "$VM_DIR"

IMG_URL=${IMG_URL:-"https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img"}
OUT_IMG="$VM_DIR/rootfs.img"
OVERLAY_IMG="$VM_DIR/ubuntu-arm64.qcow2"

NEED_DL=0
if [ ! -f "$OUT_IMG" ]; then
  NEED_DL=1
else
  SIZE=$(stat -f%z "$OUT_IMG" 2>/dev/null || stat -c%s "$OUT_IMG" 2>/dev/null || echo 0)
  if [ "${SIZE:-0}" -lt 52428800 ]; then
    echo "Existing $OUT_IMG is small (${SIZE} bytes). Re-downloading..."
    NEED_DL=1
  fi
fi

if [ "$NEED_DL" = "1" ]; then
  echo "Downloading Ubuntu ARM64 cloud image..."
  curl -L -o "$OUT_IMG" "$IMG_URL"
else
  echo "Image already present: $OUT_IMG"
fi

# Try to locate AArch64 UEFI firmware (optional)
FW_CANDIDATES=(
  "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
  "/usr/local/share/qemu/edk2-aarch64-code.fd"
  "/opt/homebrew/share/qemu/QEMU_EFI.fd"
)
for fw in "${FW_CANDIDATES[@]}"; do
  if [ -f "$fw" ]; then
    echo "$fw" > "$VM_DIR/firmware.path"
    echo "Found firmware: $fw"
    break
  fi
done

echo "OK: Ubuntu image ready at $OUT_IMG"

if [ ! -f "$OVERLAY_IMG" ]; then
  echo "Creating writable overlay $OVERLAY_IMG (8G)"
  qemu-img create -f qcow2 -b "$OUT_IMG" -F qcow2 "$OVERLAY_IMG" 8G || {
    echo "Overlay creation failed. Removing stale overlay and retrying..." >&2
    rm -f "$OVERLAY_IMG"
    qemu-img create -f qcow2 -b "$OUT_IMG" -F qcow2 "$OVERLAY_IMG" 8G
  }
else
  echo "Overlay image present: $OVERLAY_IMG"
fi

