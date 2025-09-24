#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root/recompile"
mkdir -p build/.re
: > build/.re/console.log
: > build/re-findings.log
python3 - <<'PY'
import shlex, subprocess, pathlib, re, sys
cmd = pathlib.Path("build/.re/qemu.cmd").read_text().strip()
cmd = re.sub(r'\s*"-drive"\s*"if=pflash,[^"]+"', '', cmd)     # drop extra pflash/VARs
if '-bios' not in cmd:
    cmd = cmd.replace('"-machine" "virt"', '"-machine" "virt" "-bios" "/opt/homebrew/opt/qemu/share/qemu/edk2-aarch64-code.fd"')
cmd = re.sub(r'"-cpu"\s+"max"', '"-cpu" "host"', cmd)         # HVF friendly
print("RUN:", cmd); sys.stdout.flush()
subprocess.run(shlex.split(cmd), check=True)
PY