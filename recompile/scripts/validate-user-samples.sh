#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-user-samples.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[external] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[external] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

samples=(
    "build/user-samples/copy_overrun_case:heap_overflow:memcpy"
    "build/user-samples/memmove_overrun_case:heap_overflow:memmove"
    "build/user-samples/memset_overrun_case:heap_overflow:memset"
    "build/user-samples/strcpy_overrun_case:heap_overflow:strcpy"
    "build/user-samples/strncpy_overrun_case:heap_overflow:strncpy"
    "build/user-samples/cache_release_twice:double_free:free"
    "build/user-samples/free_stack_slot:invalid_free:free"
)

for entry in "${samples[@]}"; do
    IFS=: read -r binary_path expected_class expected_operation <<<"$entry"
    output_dir="build/user-sample-regression/$(basename "$binary_path")"
    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-class "$expected_class" \
        --runner "$runner_path" \
        --output "$output_dir"
    if [[ "$expected_class" == "heap_overflow" ]]; then
        python3 - "$output_dir/findings.json" "$expected_operation" "$(basename "$binary_path")" <<'PY'
import json
import pathlib
import sys

findings_path = pathlib.Path(sys.argv[1])
expected_operation = sys.argv[2]
binary_name = sys.argv[3]

findings = json.loads(findings_path.read_text())
operations = [
    (((finding.get("evidence") or {}).get("memory") or {}).get("operation"))
    for finding in findings
    if isinstance(finding, dict)
]
if expected_operation not in operations:
    raise SystemExit(f"{binary_name}: expected operation {expected_operation}, got {operations}")
print(json.dumps({
    "binary": binary_name,
    "operation": expected_operation,
}))
PY
    fi
done

clean_samples=(
    "build/user-samples/clean_malloc_free"
    "build/user-samples/clean_bounded_memcpy"
    "build/user-samples/clean_bounded_memmove"
    "build/user-samples/clean_bounded_memset"
    "build/user-samples/clean_bounded_strcpy"
    "build/user-samples/clean_bounded_strncpy"
    "build/user-samples/fd_leak_case"
    "build/user-samples/clean_fd_close"
)

for binary_path in "${clean_samples[@]}"; do
    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-none \
        --runner "$runner_path" \
        --output "build/user-sample-regression/$(basename "$binary_path")"
done

printf '\n[external] user-style sample regression passed\n'
