#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-recc.sh only supports Linux validation.\n' >&2
    exit 1
fi

if ! command -v clang >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    printf 'validate-recc.sh requires clang or gcc in PATH.\n' >&2
    exit 1
fi

printf '[recc] building optional compiler wrapper\n'
cargo build --release -p recc
recc_path="${project_dir}/target/release/recc"

smoke_dir="${project_dir}/build/recc-smoke"
rm -rf "$smoke_dir" build/.re
mkdir -p "$smoke_dir"

cat >"${smoke_dir}/hello.c" <<'C'
#include <stdio.h>

int main(void) {
    puts("recc smoke");
    return 0;
}
C

printf '[recc] compiling sample through recc\n'
"$recc_path" "${smoke_dir}/hello.c" -o "${smoke_dir}/hello"

if [[ ! -x "${smoke_dir}/hello" ]]; then
    printf 'recc did not produce an executable: %s\n' "${smoke_dir}/hello" >&2
    exit 1
fi

if [[ "$("${smoke_dir}/hello")" != "recc smoke" ]]; then
    printf 'recc-built executable did not run correctly.\n' >&2
    exit 1
fi

manifest_path="build/.re/manifest.json"
python3 - "$manifest_path" "${smoke_dir}/hello" <<'PY'
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
binary_path = pathlib.Path(sys.argv[2]).resolve()

if not manifest_path.exists():
    raise SystemExit(f"missing recc manifest: {manifest_path}")

manifest = json.loads(manifest_path.read_text())
if pathlib.Path(manifest.get("binary", "")).resolve() != binary_path:
    raise SystemExit(f"manifest binary mismatch: {manifest.get('binary')} != {binary_path}")
if manifest.get("env", {}).get("RE_FRAMEPTR") != "1":
    raise SystemExit("manifest missing RE_FRAMEPTR=1")

print(json.dumps({
    "binary": str(binary_path),
    "manifest": str(manifest_path),
    "dsos": manifest.get("dsos", []),
}))
PY

printf '[recc] building optional LLVM pass\n'
cmake -S llvm-passes -B build/passes
cmake --build build/passes

if ! find build/passes -type f \( -name 're_bounds_pass.so' -o -name 'libre_bounds_pass.so' -o -name 're_bounds_pass.dylib' -o -name 'libre_bounds_pass.dylib' \) | grep -q .; then
    printf 'LLVM pass build did not produce a pass module under build/passes.\n' >&2
    exit 1
fi

printf '\n[recc] optional recc smoke passed\n'
