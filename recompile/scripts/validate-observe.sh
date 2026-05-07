#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-observe.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[observe] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[observe] building rerun release binary\n'
cargo build -q -p rerun --release
runner_path="./target/release/rerun"
output_root="build/observe-smoke"
rm -rf "$output_root"

assert_observation() {
    local summary_path="$1"
    local expected_status="$2"
    local expected_class="$3"
    local expected_count="$4"
    python3 - "$summary_path" "$expected_status" "$expected_class" "$expected_count" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
expected_status = sys.argv[2]
expected_class = sys.argv[3]
expected_count = int(sys.argv[4])
summary = json.loads(summary_path.read_text())

if summary.get("schema_version") != "1.0":
    raise SystemExit(f"{summary_path}: schema_version must be 1.0")
if summary.get("purpose") != "local_runtime_observation":
    raise SystemExit(f"{summary_path}: unexpected purpose {summary.get('purpose')}")
if summary.get("target_count") != 1:
    raise SystemExit(f"{summary_path}: expected one target")

target = summary["targets"][0]
if target.get("status") != expected_status:
    raise SystemExit(f"{summary_path}: expected status {expected_status}, got {target.get('status')}")
if target.get("findings_count") != expected_count:
    raise SystemExit(f"{summary_path}: expected findings_count {expected_count}, got {target.get('findings_count')}")

classes = target.get("findings_by_class") or {}
if expected_class == "__none__":
    if classes:
        raise SystemExit(f"{summary_path}: expected no finding classes, got {classes}")
else:
    if classes.get(expected_class) != expected_count:
        raise SystemExit(f"{summary_path}: missing class {expected_class} count {expected_count}: {classes}")

artifacts = target.get("artifacts") or {}
for key in ["crashpack", "findings", "evidence_pack", "analysis", "manifest"]:
    path = pathlib.Path(artifacts.get(key, ""))
    if not path.exists():
        raise SystemExit(f"{summary_path}: artifact {key} missing at {path}")

status_totals = summary.get("status_totals") or {}
if status_totals.get(expected_status) != 1:
    raise SystemExit(f"{summary_path}: status_totals missing {expected_status}: {status_totals}")

print(json.dumps({
    "summary": str(summary_path),
    "status": target.get("status"),
    "findings_count": target.get("findings_count"),
    "classes": classes,
}, sort_keys=True))
PY
}

printf '[observe] clean binary\n'
"$runner_path" observe build/user-samples/clean_malloc_free --output "$output_root/clean_malloc_free"
assert_observation "$output_root/clean_malloc_free/run-summary.json" clean __none__ 0

printf '[observe] finding binary\n'
"$runner_path" observe build/user-samples/copy_overrun_case --output "$output_root/copy_overrun_case"
assert_observation "$output_root/copy_overrun_case/run-summary.json" findings heap_overflow 1

printf '\n[observe] observe smoke passed\n'
