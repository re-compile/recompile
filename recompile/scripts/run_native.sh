#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --binary <path> [--func memcpy|free] [--out build/re-findings.log]" >&2
}

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root/recompile"

bin=""; func="memcpy"; out="build/re-findings.log"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) bin="$2"; shift 2;;
    --func) func="$2"; shift 2;;
    --out) out="$2"; shift 2;;
    *) usage; exit 2;;
  esac
done

if [[ -z "${bin}" ]]; then usage; exit 2; fi

os="$(uname -s)"
arch="$(uname -m)"

if [[ "$os" != "Linux" ]]; then
  echo "[native] This runner requires Linux with eBPF and CAP_BPF. Current OS=$os. Exiting." >&2
  exit 1
fi

# Try to locate a suitable libc
libc="/usr/lib/$(uname -m)-linux-gnu/libc.so.6"
[[ -r "$libc" ]] || libc="/lib/x86_64-linux-gnu/libc.so.6"
[[ -r "$libc" ]] || libc="/lib/aarch64-linux-gnu/libc.so.6"
[[ -r "$libc" ]] || libc="/lib/libc.so.6"

if [[ ! -r "$libc" ]]; then
  echo "[native] Could not locate libc.so.6. Use --libc by editing this script if needed." >&2
  exit 1
fi

echo "[native] Using libc: $libc"

# Ensure output exists
mkdir -p "$(dirname "$out")"
: > "$out"

cmd=(sudo -n ./runtime/agent/re-mini \
  --heap runtime/bpf/heap_tracker.bpf.o \
  --obj runtime/bpf/copy_checker.bpf.o \
  --sentinel runtime/bpf/sentinel_extra.bpf.o \
  --binary "$bin" \
  --libc "$libc" \
  --func "$func" \
  --out "$out")

echo "[native] Running: ${cmd[*]}"
"${cmd[@]}"

echo "[native] Done. Findings at $out"


