#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-escalation.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

if ! command -v valgrind >/dev/null 2>&1; then
    cat >&2 <<'MSG'
valgrind is required for escalation smoke tests.
Use the supported Docker image or install valgrind on the Linux host.
MSG
    exit 1
fi

printf '[escalation] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[escalation] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

assert_escalation_result() {
    local results_path="$1"
    local binary_name="$2"
    local expected_class="$3"

    python3 - "$results_path" "$binary_name" "$expected_class" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
binary_name = sys.argv[2]
expected_class = sys.argv[3]

if not results_path.exists():
    raise SystemExit(f"{binary_name}: missing escalation results: {results_path}")

results = json.loads(results_path.read_text())
if not isinstance(results, list) or len(results) != 1:
    raise SystemExit(f"{binary_name}: expected exactly one escalation result")

result = results[0]
if result.get("tool") != "valgrind":
    raise SystemExit(f"{binary_name}: expected valgrind result, got {result.get('tool')}")
if not result.get("tool_available"):
    raise SystemExit(f"{binary_name}: valgrind not available: {result.get('error')}")
if not result.get("success"):
    raise SystemExit(f"{binary_name}: valgrind escalation failed: {result.get('error')}")

detected = result.get("findings_detected", [])
if expected_class == "__none__":
    if result.get("confirmed"):
        raise SystemExit(f"{binary_name}: clean sample unexpectedly confirmed {detected}")
    if detected:
        raise SystemExit(f"{binary_name}: clean sample unexpectedly detected {detected}")
else:
    if not result.get("confirmed"):
        raise SystemExit(f"{binary_name}: valgrind did not confirm {expected_class}")
    if expected_class not in detected:
        raise SystemExit(f"{binary_name}: expected {expected_class}, got {detected}")

for key in ("stdout_path", "stderr_path", "report_path"):
    path = result.get(key)
    if not path or not pathlib.Path(path).exists():
        raise SystemExit(f"{binary_name}: missing {key}: {path}")

print(json.dumps({
    "binary": binary_name,
    "tool": result.get("tool"),
    "confirmed": result.get("confirmed"),
    "findings_detected": result.get("findings_detected"),
    "report": result.get("report_path"),
}))
PY
}

positive_samples=(
    "build/user-samples/copy_overrun_case:heap_overflow"
    "build/user-samples/memmove_overrun_case:heap_overflow"
    "build/user-samples/memset_overrun_case:heap_overflow"
    "build/user-samples/strcpy_overrun_case:heap_overflow"
    "build/user-samples/strncpy_overrun_case:heap_overflow"
    "build/user-samples/posix_memalign_overrun_case:heap_overflow"
    "build/user-samples/aligned_alloc_overrun_case:heap_overflow"
    "build/user-samples/strdup_overrun_case:heap_overflow"
    "build/user-samples/cache_release_twice:double_free"
    "build/user-samples/free_stack_slot:invalid_free"
    "build/user-samples/realloc_zero_double_free:double_free"
)

for entry in "${positive_samples[@]}"; do
    binary_path="${entry%%:*}"
    expected_class="${entry##*:}"
    binary_name="$(basename "$binary_path")"
    output_dir="build/escalation-smoke/${binary_name}"

    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-class "$expected_class" \
        --runner "$runner_path" \
        --output "$output_dir"

    printf '[escalation] running valgrind escalation for %s\n' "$binary_name"
    "$runner_path" escalate "$output_dir" --tool valgrind
    assert_escalation_result \
        "$output_dir/escalations/results.json" \
        "$binary_name" \
        "$expected_class"
done

valgrind_only_samples=(
    "build/user-samples/use_after_free_case:use_after_free"
    "build/user-samples/memory_leak_case:memory_leak"
    "build/user-samples/fd_leak_case:fd_leak"
)

for entry in "${valgrind_only_samples[@]}"; do
    binary_path="${entry%%:*}"
    expected_class="${entry##*:}"
    binary_name="$(basename "$binary_path")"
    output_dir="build/escalation-smoke/${binary_name}"

    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-none \
        --runner "$runner_path" \
        --output "$output_dir"

    printf '[escalation] running valgrind binary scan for %s\n' "$binary_name"
    "$runner_path" escalate "$output_dir" --tool valgrind --scan-binary
    assert_escalation_result \
        "$output_dir/escalations/results.json" \
        "$binary_name" \
        "$expected_class"
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
    "build/user-samples/clean_bounded_memcpy"
    "build/user-samples/clean_bounded_memmove"
    "build/user-samples/clean_bounded_memset"
    "build/user-samples/clean_bounded_strcpy"
    "build/user-samples/clean_bounded_strncpy"
    "build/user-samples/clean_fd_close"
)

for binary_path in "${clean_samples[@]}"; do
    binary_name="$(basename "$binary_path")"
    output_dir="build/escalation-smoke/${binary_name}"

    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-none \
        --runner "$runner_path" \
        --output "$output_dir"

    printf '[escalation] running clean valgrind check for %s\n' "$binary_name"
    "$runner_path" escalate "$output_dir" --tool valgrind --check-clean
    assert_escalation_result \
        "$output_dir/escalations/results.json" \
        "$binary_name" \
        "__none__"
done

printf '\n[escalation] valgrind escalation smoke passed\n'
