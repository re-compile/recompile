#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./scripts/validate-binary.sh --binary PATH (--expect-class CLASS | --expect-none) [options]

Runs native analysis for one Linux ELF binary and asserts either one expected
finding class or no findings. This is the bring-your-own-binary smoke path; it
is intentionally not tied to the golden examples.

Options:
  --binary PATH        Binary to analyze
  --expect-class CLASS Expected finding class, such as heap_overflow
  --expect-none        Expect findings.json to contain zero findings
  --output DIR         Output directory
                       Default: build/external-smoke/<binary-name>
  --runner PATH        Existing rerun binary
  -h, --help           Show this help
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

binary_path=""
expected_class=""
expect_none=0
output_dir=""
runner_path=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            binary_path="$2"
            shift 2
            ;;
        --expect-class)
            expected_class="$2"
            shift 2
            ;;
        --expect-none)
            expect_none=1
            shift
            ;;
        --output)
            output_dir="$2"
            shift 2
            ;;
        --runner)
            runner_path="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-binary.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

if [[ -z "$binary_path" ]]; then
    usage >&2
    exit 2
fi

if [[ -n "$expected_class" && "$expect_none" -eq 1 ]]; then
    printf 'Use either --expect-class or --expect-none, not both.\n\n' >&2
    usage >&2
    exit 2
fi

if [[ -z "$expected_class" && "$expect_none" -eq 0 ]]; then
    usage >&2
    exit 2
fi

cd "$project_dir"

if [[ ! -f "$binary_path" && -f "${project_dir}/${binary_path}" ]]; then
    binary_path="${project_dir}/${binary_path}"
fi

if [[ ! -x "$binary_path" ]]; then
    printf 'binary is not executable: %s\n' "$binary_path" >&2
    exit 1
fi

if [[ -z "$runner_path" ]]; then
    printf '[external] building rerun release binary\n'
    cargo build --release -p rerun
    runner_path="${project_dir}/target/release/rerun"
fi

if [[ ! -x "$runner_path" ]]; then
    printf 'rerun binary is not executable: %s\n' "$runner_path" >&2
    exit 1
fi

binary_name="$(basename "$binary_path")"
if [[ -z "$output_dir" ]]; then
    output_dir="${project_dir}/build/external-smoke/${binary_name}"
fi

log_path="${output_dir}.log"
rm -rf "$output_dir" "$log_path"
mkdir -p "$(dirname "$output_dir")"

if [[ "$expect_none" -eq 1 ]]; then
    expected_label="no findings"
else
    expected_label="$expected_class"
fi

printf '[external] running %s -> %s\n' "$binary_path" "$expected_label"
if ! "$runner_path" run --native "$binary_path" --output "$output_dir" >"$log_path" 2>&1; then
    printf '\n[external] run failed for %s\n' "$binary_path" >&2
    if grep -q "shared host PID namespace" "$log_path"; then
        cat >&2 <<'EOF'
Native Docker tracing is only supported with:
  docker run --rm -it --privileged --pid=host -v "$PWD":/workspace/recompile recompile-bootstrap:host bash
EOF
    fi
    printf '\n--- run log ---\n' >&2
    tail -n 80 "$log_path" >&2 || true
    exit 1
fi

python3 - "$output_dir/findings.json" "$expected_class" "$expect_none" "$binary_name" <<'PY'
import json
import pathlib
import sys

findings_path = pathlib.Path(sys.argv[1])
expected_class = sys.argv[2]
expect_none = sys.argv[3] == "1"
binary_name = sys.argv[4]

if not findings_path.exists():
    raise SystemExit(f"{binary_name}: missing findings.json at {findings_path}")

findings = json.loads(findings_path.read_text())
if not isinstance(findings, list):
    raise SystemExit(f"{binary_name}: findings.json is not a JSON array")

if expect_none:
    if findings:
        classes = [finding.get("class") for finding in findings if isinstance(finding, dict)]
        raise SystemExit(f"{binary_name}: expected no findings, got {len(findings)}: {classes}")
    print(json.dumps({
        "binary": binary_name,
        "class": None,
        "finding_count": 0,
        "output": str(findings_path.parent),
    }))
    raise SystemExit(0)

if len(findings) != 1:
    raise SystemExit(f"{binary_name}: expected exactly 1 finding, got {len(findings)}")

finding = findings[0]
actual_class = finding.get("class")
if actual_class != expected_class:
    raise SystemExit(f"{binary_name}: expected class {expected_class}, got {actual_class}")

provenance = finding.get("provenance") or {}
evidence = finding.get("evidence") or {}

print(json.dumps({
    "binary": binary_name,
    "class": actual_class,
    "severity": finding.get("severity"),
    "source_path": provenance.get("source_path"),
    "alloc_site": evidence.get("alloc_site"),
    "output": str(findings_path.parent),
}))
PY
