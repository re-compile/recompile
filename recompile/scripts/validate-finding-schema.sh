#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import json
import pathlib
import sys
from typing import Any

root = pathlib.Path.cwd()
schema_path = root / "schemas" / "finding.schema.json"
schema = json.loads(schema_path.read_text())


def resolve_ref(ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise AssertionError(f"unsupported $ref {ref}")
    node: Any = schema
    for part in ref[2:].split('/'):
        node = node[part]
    return node


def type_ok(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    raise AssertionError(f"unsupported schema type {expected}")


def validate(value: Any, node: dict[str, Any], path: str = "$") -> list[str]:
    if "$ref" in node:
        return validate(value, resolve_ref(node["$ref"]), path)

    errors: list[str] = []

    if "anyOf" in node:
        branch_errors = [validate(value, branch, path) for branch in node["anyOf"]]
        if all(branch for branch in branch_errors):
            errors.append(f"{path}: did not match any anyOf branch: {branch_errors}")

    if "type" in node:
        expected_types = node["type"]
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        if not any(type_ok(value, expected) for expected in expected_types):
            errors.append(f"{path}: expected type {expected_types}, got {type(value).__name__}")
            return errors

    if "enum" in node and value not in node["enum"]:
        errors.append(f"{path}: value {value!r} is not in enum {node['enum']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool) and "minimum" in node:
        if value < node["minimum"]:
            errors.append(f"{path}: value {value} < minimum {node['minimum']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and "maximum" in node:
        if value > node["maximum"]:
            errors.append(f"{path}: value {value} > maximum {node['maximum']}")

    if isinstance(value, str) and "minLength" in node:
        if len(value) < node["minLength"]:
            errors.append(f"{path}: string shorter than minLength {node['minLength']}")

    if isinstance(value, dict):
        for key in node.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required key {key}")
        properties = node.get("properties", {})
        for key, child in value.items():
            if key in properties:
                errors.extend(validate(child, properties[key], f"{path}.{key}"))
            elif node.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected key {key}")

    if isinstance(value, list) and "items" in node:
        for index, item in enumerate(value):
            errors.extend(validate(item, node["items"], f"{path}[{index}]"))

    return errors


def check(name: str, finding: dict[str, Any]) -> None:
    errors = validate(finding, schema)
    if errors:
        raise SystemExit(f"{name} failed finding schema validation:\n" + "\n".join(errors))


stream_location = {
    "uri": "file:///tmp/example.c",
    "range": {"start": {"line": 1, "character": 0}, "end": {"line": 1, "character": 1}},
}

representative = {
    "agent_stream_heap": {
        "id": "F-heap-overflow-1",
        "origin": "ebpf",
        "kind": "heap_overflow",
        "severity": "error",
        "message": "memcpy overflow",
        "primaryLocation": stream_location,
        "evidence": {
            "api": "memcpy",
            "len": 80,
            "dest_alloc": {"ptr": "0x1000", "size": 24},
            "stacks": {"alloc": ["packet_new example.c:1"], "call": ["main example.c:2"]},
        },
        "fixHints": ["Bound copy length"],
        "dataQuality": {"eventsDropped": 0},
    },
    "native_heap_crashpack": {
        "schema_version": "1.0",
        "id": "F-heap-overflow-2",
        "class": "heap_overflow",
        "confidence": "high",
        "severity": "error",
        "timestamp": 1,
        "pid": 42,
        "evidence": {
            "memory": {"ptr": 4096, "size": 80, "alloc_size": 24, "operation": "memcpy"},
            "stacks": {"alloc": ["packet_new example.c:1"], "call": ["main example.c:2"]},
            "alloc_site": "/tmp/example.c",
        },
        "escalation": {"tool": "asan", "reason": "len>alloc_size", "estimated_cost": "low", "cooldown_ms": 10000},
        "provenance": {"source_status": "resolved", "source_path": "/tmp/example.c"},
        "related": [],
    },
    "fd_lifecycle": {
        "schema_version": "1.0",
        "id": "F-double-close-1",
        "class": "double_close",
        "confidence": "high",
        "severity": "high",
        "timestamp": 2,
        "pid": 42,
        "evidence": {
            "resource": {"type": "fd", "fd": 3, "operation": "double_close", "return_value": -1},
            "stacks": {"open": ["open_file example.c:3"], "action": ["close_file example.c:4"]},
        },
        "related": [],
    },
    "runtime_crash": {
        "schema_version": "1.0",
        "id": "F-unclassified-crash-1",
        "origin": "runtime",
        "kind": "unclassified_crash",
        "class": "unclassified_crash",
        "confidence": "observed",
        "severity": "error",
        "timestamp": 3,
        "pid": 0,
        "message": "target terminated with SIGSEGV",
        "primaryLocation": stream_location,
        "evidence": {
            "api": "crash_observed",
            "crash": {"signal": 11, "signal_name": "SIGSEGV", "exit_code": None, "duration_ms": 9, "binary_path": "./app", "args": [], "cwd": "."},
            "stacks": {"crash": ["#0 main at example.c:7"]},
            "tool": {"gdb": {"signal_name": "SIGSEGV", "registers": []}},
            "event_sequence": [{"source": "runtime", "event": "target_exit_signal"}],
        },
        "provenance": {"source_status": "unresolved"},
        "next_commands": ["rerun summarize crashpack --format json"],
        "related": [],
    },
    "valgrind_uaf": {
        "schema_version": "1.0",
        "id": "F-valgrind-use-after-free-1",
        "origin": "valgrind",
        "class": "use_after_free",
        "confidence": "tool_confirmed",
        "severity": "critical",
        "timestamp": 4,
        "pid": 0,
        "evidence": {"api": "valgrind", "tool": {"name": "valgrind"}, "stacks": {"call": ["main example.c:5"]}},
        "related": [],
    },
    "asan_double_free": {
        "schema_version": "1.0",
        "id": "F-asan-double-free-1",
        "origin": "asan",
        "class": "double_free",
        "confidence": "tool_confirmed",
        "severity": "critical",
        "timestamp": 5,
        "pid": 0,
        "evidence": {"api": "asan", "tool": {"name": "asan"}, "stacks": {"free": ["cleanup example.c:6"]}},
        "related": [],
    },
    "lsan_memory_leak": {
        "schema_version": "1.0",
        "id": "F-lsan-memory-leak-1",
        "origin": "lsan",
        "class": "memory_leak",
        "confidence": "tool_confirmed",
        "severity": "warning",
        "timestamp": 6,
        "pid": 0,
        "evidence": {"api": "lsan", "tool": {"name": "lsan"}, "stacks": {"alloc": ["allocate example.c:7"]}},
        "related": [],
    },
    "ubsan_signed_overflow": {
        "schema_version": "1.0",
        "id": "F-ubsan-signed-overflow-1",
        "origin": "ubsan",
        "class": "signed_integer_overflow",
        "confidence": "tool_confirmed",
        "severity": "error",
        "timestamp": 7,
        "pid": 0,
        "evidence": {"api": "ubsan", "tool": {"name": "ubsan"}, "stacks": {"call": ["math example.c:8"]}},
        "related": [],
    },
    "gdb_crash": {
        "schema_version": "1.0",
        "id": "F-gdb-crash-1",
        "origin": "gdb",
        "class": "unclassified_crash",
        "confidence": "tool_confirmed",
        "severity": "error",
        "timestamp": 8,
        "pid": 0,
        "evidence": {"api": "gdb", "tool": {"name": "gdb"}, "stacks": {"crash": ["#0 main at example.c:9"]}},
        "related": [],
    },
}

for name, finding in representative.items():
    check(name, finding)

build_files = sorted((root / "build").glob("**/findings.json")) if (root / "build").exists() else []
validated_build_findings = 0
for path in build_files:
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise SystemExit(f"{path}: findings.json must be a list")
    for index, finding in enumerate(data):
        check(f"{path}[{index}]", finding)
        validated_build_findings += 1

print(json.dumps({
    "schema": str(schema_path),
    "representative_findings": sorted(representative),
    "build_findings_validated": validated_build_findings,
}, sort_keys=True))
PY

printf '\n[finding-schema] validation passed\n'
