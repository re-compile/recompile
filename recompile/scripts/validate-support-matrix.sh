#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"
cd "$project_dir"

python3 - <<'PY'
import json
import pathlib
import re

root = pathlib.Path('.')
matrix_path = root / 'docs' / 'support-matrix.json'
matrix = json.loads(matrix_path.read_text())

allowed_statuses = set(matrix.get('status_values') or [])
required_top = {'schema_version', 'purpose', 'scope', 'status_values', 'classes'}
missing_top = required_top - set(matrix)
if missing_top:
    raise SystemExit(f'{matrix_path}: missing top-level keys: {sorted(missing_top)}')
if matrix.get('purpose') != 'phase5_support_matrix':
    raise SystemExit(f'{matrix_path}: unexpected purpose: {matrix.get("purpose")}')

entries = matrix.get('classes')
if not isinstance(entries, list) or not entries:
    raise SystemExit(f'{matrix_path}: classes must be a non-empty array')

by_class = {}
for entry in entries:
    cls = entry.get('class')
    if not cls or not isinstance(cls, str):
        raise SystemExit(f'{matrix_path}: every entry needs a string class: {entry}')
    if cls in by_class:
        raise SystemExit(f'{matrix_path}: duplicate class {cls}')
    by_class[cls] = entry
    native = entry.get('native') or {}
    native_status = native.get('status')
    if native_status not in allowed_statuses:
        raise SystemExit(f'{cls}: native.status {native_status!r} is not in status_values')
    if not native.get('evidence'):
        raise SystemExit(f'{cls}: native.evidence is required')
    for list_key in ('positive_cases', 'clean_negative_cases'):
        if list_key not in native or not isinstance(native[list_key], list):
            raise SystemExit(f'{cls}: native.{list_key} must be an array')
    tools = entry.get('tools') or {}
    if not isinstance(tools, dict) or not tools:
        raise SystemExit(f'{cls}: tools must be a non-empty object')
    for tool, status in tools.items():
        if status not in allowed_statuses:
            raise SystemExit(f'{cls}: tools.{tool} status {status!r} is not in status_values')
    if native_status in {'supported', 'observed_only'} and not native['positive_cases']:
        raise SystemExit(f'{cls}: native {native_status} requires positive_cases')
    if native_status == 'supported' and not native['clean_negative_cases']:
        raise SystemExit(f'{cls}: native supported requires clean_negative_cases')
    if not entry.get('limitations'):
        raise SystemExit(f'{cls}: limitations must be explicit')

class_token = r'[A-Za-z0-9_]+'
expected_classes = set()

hit_rate = (root / 'scripts' / 'validate-hit-rate.sh').read_text()
for match in re.finditer(r'^\s*"([^":]+):([^":]+):([^":]+):(\d+)"', hit_rate, re.M):
    for token in match.group(2, 3):
        if not token.startswith('__'):
            expected_classes.add(token)

observe = (root / 'scripts' / 'validate-observe-hit-rate.sh').read_text()
for match in re.finditer(r'^run_observe_case\s+\S+\s+\S+\s+(\S+)\s+\d+\s+\S+\s+\S+\s+(\S+)', observe, re.M):
    for token in match.group(1, 2):
        if not token.startswith('__'):
            expected_classes.add(token)

observe_smoke = (root / 'scripts' / 'validate-observe.sh').read_text()
for match in re.finditer(r'^assert_observation\s+\S+\s+\S+\s+(\S+)\s+\d+', observe_smoke, re.M):
    token = match.group(1)
    if not token.startswith('__'):
        expected_classes.add(token)

asan = (root / 'scripts' / 'validate-asan.sh').read_text()
for match in re.finditer(r'assert_asan_confirmed\s+\\\n\s+"[^\n]+"\s+\\\n\s+"[^\n]+"\s+\\\n\s+"([^"\n]+)"', asan):
    expected_classes.add(match.group(1))

lsan = (root / 'scripts' / 'validate-lsan.sh').read_text()
if 'memory_leak' in lsan:
    expected_classes.add('memory_leak')

ubsan = (root / 'scripts' / 'validate-ubsan.sh').read_text()
for match in re.finditer(r'^run_positive\s+\S+\s+(' + class_token + r')\s*$', ubsan, re.M):
    expected_classes.add(match.group(1))

missing = sorted(expected_classes - set(by_class))
if missing:
    raise SystemExit(f'{matrix_path}: validation scripts reference classes missing from matrix: {missing}')

unvalidated_native_claims = []
validated_native_classes = set()
for cls in expected_classes:
    entry = by_class[cls]
    if (entry.get('native') or {}).get('status') in {'supported', 'observed_only'}:
        validated_native_classes.add(cls)
for cls, entry in by_class.items():
    native = entry.get('native') or {}
    if native.get('status') in {'supported', 'observed_only'} and cls not in expected_classes:
        unvalidated_native_claims.append(cls)
if unvalidated_native_claims:
    raise SystemExit(f'{matrix_path}: native-supported/observed classes lack validation references: {sorted(unvalidated_native_claims)}')

summary = {
    'schema_version': matrix['schema_version'],
    'total_classes': len(by_class),
    'validation_referenced_classes': sorted(expected_classes),
    'native_validated_classes': sorted(validated_native_classes),
    'not_covered_classes': sorted(
        cls for cls, entry in by_class.items()
        if (entry.get('native') or {}).get('status') == 'not_covered'
    ),
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY

printf '\n[support-matrix] validation passed\n'
