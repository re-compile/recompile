#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KDIR="$ROOT/runtime/vm/kernel"
mkdir -p "$KDIR"

V_URL=${V_URL:-"https://cloud-images.ubuntu.com/jammy/current/unpacked/jammy-server-cloudimg-arm64-vmlinuz-generic"}
I_URL=${I_URL:-"https://cloud-images.ubuntu.com/jammy/current/unpacked/jammy-server-cloudimg-arm64-initrd-generic"}

if [ ! -f "$KDIR/vmlinuz" ]; then
  echo "Downloading kernel vmlinuz..."
  curl -L -o "$KDIR/vmlinuz" "$V_URL"
else
  echo "Kernel present: $KDIR/vmlinuz"
fi

if [ ! -f "$KDIR/initrd" ]; then
  echo "Downloading initrd..."
  curl -L -o "$KDIR/initrd" "$I_URL"
else
  echo "Initrd present: $KDIR/initrd"
fi

echo "OK: kernel+initrd ready under $KDIR"

