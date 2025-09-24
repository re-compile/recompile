#!/usr/bin/env bash
set -euo pipefail
dst="runtime/bpf/include/bpf"
mkdir -p "$dst"
# Pick a stable libbpf tag. v1.4.0 is fine for 5.15 kernels.
base="https://raw.githubusercontent.com/libbpf/libbpf/v1.4.0/src"
for f in bpf_helpers.h bpf_tracing.h bpf_core_read.h bpf_endian.h bpf_helper_defs.h; do
  curl -fsSL "$base/$f" -o "$dst/$f"
done
echo "Fetched headers into $dst:"
ls -1 "$dst"
