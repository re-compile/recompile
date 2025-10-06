#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root/recompile"

# Fresh run
bash scripts/reseed.sh >/dev/null
: > build/.re/console.log
: > build/re-findings.log
timeout 180 bash scripts/re-qemu.sh || true

python3 scripts/make_crashpack.py build/re-findings.log build/.re/console.log build/crashpack-lite >/dev/null

# Simple validation: ensure at least one RE:FINDING present
if ! rg -n "^RE:FINDING:" build/re-findings.log >/dev/null; then
  echo "[FAIL] no findings found" >&2
  exit 1
fi
echo "[OK] findings present; crashpack-lite built"


