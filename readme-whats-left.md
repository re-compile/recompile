RECC Sentinel – One-Week Speedrun Plan

Goal:
Ship the first full-scope RECC MVP — an intelligent, autonomous debugging companion for C/C++ that detects, classifies, and reproduces runtime issues automatically.

Status: eBPF Fast-Triage Complete (heap_overflow, double_free, invalid_free, use_after_free)
Focus: Everything above that pipeline — rule engine, escalation, crashpack, symbolization, and clustering.

⸻

⚙️ Architecture Freeze

Component	Responsibility	Status
eBPF Sentinel	Kernel-level probes for heap ops, memcpy/memmove, locks, and syscalls	✅ Functional
Agent (Rust)	Event collector, normalizer, rule engine host, findings emitter	🟢 Ready for extension
Escalation Runner	Orchestrates sanitizer/Valgrind/GDB replays per finding	🔴 To Implement
Crashpack Generator	Creates minimal repro harness + artifacts for each finding	🔴 To Implement
Symbolizer Shim	Lightweight DWARF addr→func mapping (llvm-symbolizer preferred)	🟡 Basic ready, extend
Clustering Engine	De-dupe + confidence merging + multi-error grouping	🔴 To Implement


⸻

Implementation Roadmap 

Spec & Interface Lock
	•	Treat re_events.h as source of truth for event model.
	•	Finalize mapping to readme-interfaces&schemas.md for JSON emission.
	•	Define escalation thresholds & timeouts:
	•	Auto-escalate for heap_overflow, invalid_free, double_free, uaf-hint.
	•	Escalation timeout = 120 s; total per-run budget = 10 min.
	•	Crashpack layout (freeze):

crashpack/
 ├─ findings.json
 ├─ console.log
 ├─ repro.sh
 ├─ env.txt
 ├─ build.json
 ├─ inputs/
 ├─ symbols/
 └─ escalations/
      ├─ asan/
      ├─ valgrind/
      └─ gdb/


	•	Add “fast-fail if compile_commands.json missing” (with hint to run bear -- make).
	•	Symbolizer preference: llvm-symbolizer → addr2line → raw PCs.

⸻

Ingestion + Symbolization
	•	Finalize ringbuf consumer (bounded batch loop, backpressure, drop counters).
	•	Normalize events → canonical structs (ptr, size, len, api, stacks, ts).
	•	Implement symbolizer shim:

llvm-symbolizer -inlining -demangle -obj <binary> <addr>

fallback to addr2line -Cfise.

	•	Add --no-symbolize flag for CI.
	•	Unit tests: verify top N frames + demangling.

Deliverable: Symbolization pipeline stable; raw PCs + demangled frames appear in findings.

⸻

Rule Engine + Clustering
	•	Implement rules:
	•	memcpy/memmove len > alloc.size → heap_overflow
	•	free(non-tracked) → invalid_free
	•	free(already freed) → double_free
	•	memcpy to freed ptr → uaf-hint (confidence 0.7)
	•	realloc misuse → realloc_leak or dangling_realloc
	•	Include evidence:

"evidence": {
  "memory": {"ptr":"0x...", "size":64},
  "stacks": {"alloc": [...], "call": [...]},
  "alloc_site": "foo.c:42"
}


	•	Add per-rule debounce config:

"debounce": {"window_ms":1500,"min_hits":2}


	•	Implement cluster fingerprint = hash(kind + top2 frames + ptr bucket).
	•	Emit only one finding per cluster; track hits.

Deliverable: Each example → 1 canonical finding; duplicates suppressed.

⸻

Escalation Runner
	•	Implement orchestrator:
	•	ASan path:

RE_SANITIZE=address ./build/target ...

parse stdout for ==ERROR: AddressSanitizer.

	•	Valgrind path:

valgrind --error-exitcode=99 --leak-check=full --track-origins=yes ...

parse “Invalid read/write” blocks; store as JSON.

	•	GDB fallback:

gdb -batch -ex run -ex bt -ex info reg <target>


	•	Policy:
	•	Trigger if confidence < 1.0 or explicit --force-escalate.
	•	Attach parsed artifacts under finding.escalation.
	•	Confidence merge:
	•	Escalator evidence overrides triage if same kind.
	•	Conflicting kinds → related[] sub-finding.

Deliverable: --escalate {auto|always|never} flag operational; escalations written to crashpack.

⸻

Crashpack + Repro Harness
	•	Generate repro.sh:

#!/bin/bash
export ASAN_OPTIONS=detect_leaks=1
export RE_SEED=12345
./target "$@" < inputs/input.bin


	•	Capture runtime env: argv, env vars, cwd, compiler version, RECC commit.
	•	Add /proc/maps + kernel info to env.txt.
	•	Capture stdin/file inputs under inputs/.
	•	Optional coarse input minimization: truncate to ¼ size if deterministic crash.
	•	Produce manifest.json with:

{"version":"0.1.0","kernel":"5.15","commit":"abc123","toolchain":"clang 17"}



Deliverable: Unzip crashpack → bash repro.sh reproduces finding.

⸻

Polish, Perf, Docs
	•	Measure probe overhead (< 3 µs per event).
	•	Add watchdog for sanitizer jobs.
	•	Improve agent shutdown + drop reporting.
	•	Write internal doc: “How to interpret a finding” (triage + escalated examples).
	•	Add sample JSON templates for each error kind.

⸻

Validation & Release Cut
	•	Fuzz random sizes + bad frees (agent must never segfault).
	•	Run both examples under VM + native; compare findings (must be schema-identical).
	•	Negative test: no findings for clean code.
	•	Tag release v0.1.0-sentinel-mvp.
	•	Write changelog + quickstart:

re run --native ./examples/double_free
re run --escalate auto ./examples/memcpy_overflow



⸻

✅ Deliverables Checklist
	•	Fast-triage eBPF probes (heap + memcpy)
	•	Rule Engine & clustering
	•	Escalation Runner (ASan/Valgrind/GDB)
	•	Crashpack-v1 + Repro Harness
	•	Symbolization polish
	•	Docs + Tests + Release tag

⸻

💡 Notes / Implementation Details
	•	Keymaps:
	•	sentinel_state key: __u32 pid
	•	io_/mutex_/futex_pending: __u64 pid_tgid
	•	Always use 8-byte stack slots for verifier alignment.
	•	Confidence semantics:
	•	1.0 = deterministic proof
	•	0.7 = heuristic hint
	•	0.5 = incomplete evidence (escalate)
	•	Finding ID format:

F-{kind}-{hash:08x}-{timestamp}


	•	Logs:
	•	Human: build/re-findings.log
	•	Machine: build/.re/last_finding.json
	•	Native mode:
Requires CAP_BPF + CAP_PERFMON; fallback to VM if unavailable.

⸻

🎯 End Goal

By the end of this sprint, RECC will:
	•	Catch > 95% of all runtime memory issues in C/C++ (heap, stack, global, leaks, uninit).
	•	Auto-triage and selectively escalate to sanitizers.
	•	Generate deterministic repro harnesses (Crashpacks).
	•	Provide clean, unified findings developers can act on immediately.
	•	Serve as the only tool C/C++ devs need for runtime debugging.

⸻

🧾 Example Acceptance Runs

# 1. Fast-triage only
re run --native ./examples/memcpy_overflow
# → emits heap_overflow with alloc+call stack

# 2. Auto-escalate to ASan
re run --escalate auto ./examples/double_free
# → runs ASan, merges findings, writes crashpack/

# 3. Generate crashpack + repro
tar -xzf build/crashpacks/F-double_free.tar.gz
bash crashpack/repro.sh
# → reproduces same finding

