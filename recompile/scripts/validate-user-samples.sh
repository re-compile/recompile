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
    "build/user-samples/posix_memalign_overrun_case:heap_overflow:memset"
    "build/user-samples/aligned_alloc_overrun_case:heap_overflow:memset"
    "build/user-samples/strdup_overrun_case:heap_overflow:memset"
    "build/user-samples/cache_release_twice:double_free:free"
    "build/user-samples/free_stack_slot:invalid_free:free"
    "build/user-samples/realloc_zero_double_free:double_free:free"
    "build/user-samples/cxx_new_free_mismatch:allocator_mismatch:free:new:free"
    "build/user-samples/cxx_malloc_delete_mismatch:allocator_mismatch:delete:malloc:delete"
    "build/user-samples/cxx_new_array_delete_mismatch:allocator_mismatch:delete:new[]:delete"
    "build/user-samples/cxx_new_delete_array_mismatch:allocator_mismatch:delete[]:new:delete[]"
    "build/user-samples/fd_leak_case:fd_leak:fd_leak"
    "build/user-samples/fd_double_close_case:double_close:double_close"
    "build/user-samples/fd_invalid_close_case:invalid_close:invalid_close"
    "build/user-samples/fd_dup_leak_case:fd_leak:fd_leak"
    "build/user-samples/fd_dup2_leak_case:fd_leak:fd_leak"
)

for entry in "${samples[@]}"; do
    IFS=: read -r binary_path expected_class expected_operation expected_alloc_family expected_dealloc_family <<<"$entry"
    output_dir="build/user-sample-regression/$(basename "$binary_path")"
    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-class "$expected_class" \
        --runner "$runner_path" \
        --output "$output_dir"
    if [[ -n "$expected_operation" ]]; then
        python3 - "$output_dir/findings.json" "$expected_operation" "${expected_alloc_family:-}" "${expected_dealloc_family:-}" "$(basename "$binary_path")" <<'PY'
import json
import pathlib
import sys

findings_path = pathlib.Path(sys.argv[1])
expected_operation = sys.argv[2]
expected_alloc_family = sys.argv[3]
expected_dealloc_family = sys.argv[4]
binary_name = sys.argv[5]

findings = json.loads(findings_path.read_text())
memory_blocks = [
    ((finding.get("evidence") or {}).get("memory") or {})
    for finding in findings
    if isinstance(finding, dict)
]
resource_blocks = [
    ((finding.get("evidence") or {}).get("resource") or {})
    for finding in findings
    if isinstance(finding, dict)
]
operations = [memory.get("operation") for memory in memory_blocks] + [
    resource.get("operation") for resource in resource_blocks
]
if expected_operation not in operations:
    raise SystemExit(f"{binary_name}: expected operation {expected_operation}, got {operations}")
if expected_alloc_family:
    alloc_families = [memory.get("alloc_family") for memory in memory_blocks]
    if expected_alloc_family not in alloc_families:
        raise SystemExit(f"{binary_name}: expected alloc_family {expected_alloc_family}, got {alloc_families}")
if expected_dealloc_family:
    dealloc_families = [memory.get("dealloc_family") for memory in memory_blocks]
    if expected_dealloc_family not in dealloc_families:
        raise SystemExit(f"{binary_name}: expected dealloc_family {expected_dealloc_family}, got {dealloc_families}")
print(json.dumps({
    "binary": binary_name,
    "operation": expected_operation,
    "alloc_family": expected_alloc_family or None,
    "dealloc_family": expected_dealloc_family or None,
}))
PY
    fi
done

clean_samples=(
    "build/user-samples/clean_malloc_free"
    "build/user-samples/clean_realloc_grow"
    "build/user-samples/clean_failed_realloc"
    "build/user-samples/clean_realloc_null"
    "build/user-samples/clean_realloc_zero"
    "build/user-samples/clean_posix_memalign"
    "build/user-samples/clean_aligned_alloc"
    "build/user-samples/clean_strdup"
    "build/user-samples/clean_cxx_new_delete"
    "build/user-samples/clean_bounded_memcpy"
    "build/user-samples/clean_bounded_memmove"
    "build/user-samples/clean_bounded_memset"
    "build/user-samples/clean_bounded_strcpy"
    "build/user-samples/clean_bounded_strncpy"
    "build/user-samples/clean_fd_close"
    "build/user-samples/clean_fd_dup_close"
    "build/user-samples/clean_fd_dup2_replace"
    "build/user-samples/clean_fd_fcntl_dup_close"
)

for binary_path in "${clean_samples[@]}"; do
    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-none \
        --runner "$runner_path" \
        --output "build/user-sample-regression/$(basename "$binary_path")"
done

printf '\n[external] user-style sample regression passed\n'
