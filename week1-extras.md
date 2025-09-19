re:compile — Week 1 Extras (Schema, Signals, Breadcrumbs, Symbolization, Tests, Perf)

This file clarifies the Week‑1 MVP choices explicitly so you can code & test without ambiguity.

⸻

1) Finding JSON Schema (draft v1)

Required fields: id, origin, kind, severity, primaryLocation, evidence

{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "re:compile Finding v1",
  "type": "object",
  "required": ["id", "origin", "kind", "severity", "primaryLocation", "evidence"],
  "properties": {
    "id": {"type": "string"},
    "origin": {"type": "string", "enum": ["ebpf", "asan", "ubsan", "lsan", "tsan", "msan", "rr"]},
    "kind": {"type": "string", "enum": [
      "heap_overflow", "stack_overflow", "use_after_free", "double_free", "invalid_free",
      "leak", "race", "uninitialized_read", "segfault", "ub", "fd_leak", "thread_leak"
    ]},
    "severity": {"type": "string", "enum": ["note", "warning", "error"]},
    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    "primaryLocation": {
      "type": "object",
      "required": ["uri", "range"],
      "properties": {
        "uri": {"type": "string"},
        "range": {
          "type": "object",
          "required": ["start", "end"],
          "properties": {
            "start": {"type": "object", "required": ["line", "character"], "properties": {"line": {"type": "integer", "minimum": 0}, "character": {"type": "integer", "minimum": 0}}},
            "end":   {"type": "object", "required": ["line", "character"], "properties": {"line": {"type": "integer", "minimum": 0}, "character": {"type": "integer", "minimum": 0}}}
          }
        }
      }
    },
    "evidence": {
      "type": "object",
      "properties": {
        "api": {"type": "string"},
        "len": {"type": "integer", "minimum": 0},
        "memory": {"type": "object", "properties": {"ptr": {"type": "string"}, "size": {"type": "integer", "minimum": 0}}},
        "dest_alloc": {"type": "object", "properties": {"ptr": {"type": "string"}, "size": {"type": "integer"}}},
        "stacks": {"type": "object", "properties": {
          "alloc": {"type": "array", "items": {"type": "string"}},
          "call":  {"type": "array", "items": {"type": "string"}},
          "crash": {"type": "array", "items": {"type": "string"}}
        }}
      }
    },
    "breadcrumbs": {"type": "array", "items": {"type": "string"}},
    "codeFlow": {"type": "array", "items": {"type": "object"}},
    "fixHints": {"type": "array", "items": {"type": "string"}},
    "relatedLocations": {"type": "array", "items": {"type": "object"}},
    "dataQuality": {"type": "object", "properties": {"eventsDropped": {"type": "integer", "minimum": 0}}}
  }
}

Minimal instance (Week‑1 example)

{
  "id": "F-heap-overflow-001",
  "origin": "ebpf",
  "kind": "heap_overflow",
  "severity": "error",
  "primaryLocation": {"uri": "file:///examples/memcpy_overflow.c", "range": {"start": {"line": 23, "character": 10}, "end": {"line": 23, "character": 16}}},
  "evidence": {
    "api": "memcpy",
    "len": 64,
    "dest_alloc": {"ptr": "0x7f...", "size": 32},
    "stacks": {
      "alloc": ["examples/memcpy_overflow.c:12: makeBuf"],
      "call":  ["examples/memcpy_overflow.c:23: memcpy"]
    }
  },
  "fixHints": ["Bound len to capacity", "Allocate len bytes"]
}


⸻

2) Signal Handling Strategy (Week‑1)
	•	No in‑process handler injection; no LD_PRELOAD.
	•	VM Agent supervises the target (e.g., ptrace(SEIZE) or waitpid). On crash (SIGSEGV/SIGABRT):
	•	Record signal and (if available) siginfo_t.si_addr.
	•	Attach the last‑N call‑site stacks we already captured for memcpy/free.
	•	Emit a kind: "segfault" finding if we have no direct mem* overflow. Otherwise, the heap_overflow finding remains primary.
	•	Auto‑escalation: if attribution is weak (no mem* cause, no alloc correlation), we re‑run with ASan and merge the result.
	•	Week‑2 upgrade: attach BPF signal:signal_deliver and capture a crash user stack via bpf_get_stackid.

⸻

3) Event Path for Breadcrumbs (Week‑1 → Week‑2)
	•	Week‑1 choice (simplest): optional stdout breadcrumbs from the LLVM pass.
	•	Format (one line per site): RE:BREADCRUMB <site-id> <phase> <tid> <pc>
	•	site-id = stable hash of (CU, line, col, discriminator, function).
	•	Default OFF; enable with --debug-breadcrumbs for troubleshooting.
	•	Primary signals in Week‑1 still come from eBPF (alloc/memcpy/free + stacks); breadcrumbs are supplemental.
	•	Week‑2: switch to real markers (USDT/perf) for zero‑alloc logging and precise correlation; keep stdout mode as a debug fallback.

⸻

4) Symbolization Scope (Week‑1)
	•	Accept raw addresses (hex PCs) + module names in stacks and breadcrumbs.
	•	If llvm-symbolizer is present in the VM image, we symbolize; otherwise we write raw PCs and symbolize later.
	•	Required compile flags remain -g -fno-omit-frame-pointer to keep unwinding stable.

Manual symbolization cmd

llvm-symbolizer --inlines --demangle --obj=./build/a.out 0x40123a

	•	Week‑2: formalize symbolization (always invoke llvm-symbolizer in agent) and add -ginline-info -gcolumn-info for better ranges.

⸻

5) Testing Strategy (Week‑1)

Examples (examples/):
	•	memcpy_overflow.c → expect kind=heap_overflow, evidence.len > evidence.dest_alloc.size.
	•	double_free.c → expect kind=double_free.
	•	invalid_free.c → expect kind=invalid_free.
	•	(optional) segv_null.c → expect kind=segfault (auto‑escalates to ASan if attribution weak).

Golden test harness (scripts/test-smoke.sh):

#!/usr/bin/env bash
set -euo pipefail

run_and_grab() {
  local bin=$1; shift
  re run "$bin" "$@" | tee /tmp/re.out
  # Extract JSON block (assuming agent prints it on a dedicated line)
  grep -a "^RE:FINDING:" /tmp/re.out | sed 's/^RE:FINDING: //' > /tmp/re.finding.json
}

validate_schema() {
  # Minimal checks with jq (schema validation can be added with ajv later)
  jq -e '.id and .origin and .kind and .severity and .primaryLocation and .evidence' /tmp/re.finding.json > /dev/null
}

check_overflow_invariants() {
  local k=$(jq -r '.kind' /tmp/re.finding.json)
  if [[ "$k" == "heap_overflow" ]]; then
    jq -e '.evidence.len > .evidence.dest_alloc.size' /tmp/re.finding.json > /dev/null
  fi
}

run_and_grab ./examples/memcpy_overflow
validate_schema
check_overflow_invariants

run_and_grab ./examples/double_free
validate_schema

run_and_grab ./examples/invalid_free
validate_schema

echo "OK: smoke tests passed"

Store golden JSON under examples/golden/*.json and compare subsets (ignore dynamic addresses) if you want deterministic output checks.

⸻

6) Perf Constraints (Week‑1 guardrails)
	•	Target: fast‑triage overhead on small examples ≤ 1.2× wall‑clock vs an uninstrumented run.
	•	Hard cap: ≤ 2×. If exceeded, print a perf warning.
	•	Data quality: require dataQuality.eventsDropped == 0 on examples.

Perf check snippet (scripts/perf-guard.sh):

#!/usr/bin/env bash
set -euo pipefail
BIN=$1

baseline() { /usr/bin/time -f %e "$BIN" >/dev/null 2>&1; }
with_re() { /usr/bin/time -f %e re run "$BIN" >/dev/null 2>&1; }

b=$(baseline)
r=$(with_re)
ratio=$(python3 - <<EOF
b=$b; r=$r
print(r/b)
EOF
)

awk -v x="$ratio" 'BEGIN{ if (x>2.0) { print "FAIL: overhead",x; exit 1 } else { print "OK: overhead",x; exit 0 } }'

Tuning knobs (env/manifest)
	•	stack_depth (default 64)
	•	ringbuf_mb (default 16)
	•	memcpy sampling (off in Week‑1; add in Week‑2)

⸻

TL;DR for Week‑1
	•	Schema is locked (draft v1) so tests are reproducible.
	•	Crashes are captured by the supervisor process (no in‑proc signals); weakly attributed crashes auto‑escalate to ASan.
	•	Breadcrumbs: stdout lines in Week‑1 (optional), USDT/perf in Week‑2.
	•	Stacks can be raw PCs this week; symbolize when available.
	•	Smoke tests + perf guard scripts included; aim for ≤1.2× typical, cap at 2×.