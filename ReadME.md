re:compile — AI‑Native C/C++ Compiler & MCP Server

Goal: A drop‑in C/C++ compiler + MCP server that automatically triages segmentation faults, memory errors, resource leaks, and common concurrency issues without a separate debugger. Default runs execute your program inside a microVM with low‑overhead eBPF probes plus required LLVM IR breadcrumbs; when needed, the same UX escalates to sanitizer modes (ASan/UBSan/LSan, TSan, MSan) and optional rr for deterministic replay. Findings appear as terminal diagnostics, editor highlights (LSP), and MCP JSON for agents (e.g., Cursor).

⸻

Table of Contents
	•	Why re:compile
	•	High‑Level Architecture
	•	Quickstart
	•	Repository Layout
	•	Runtime Data Model (Findings)
	•	Compile‑Time Components
	•	Runtime Components
	•	Symbolization Requirements & Fallbacks
	•	MicroVM & Native Modes
	•	MCP Server (Cursor/Agents)
	•	Escalation Path (Orchestration)
	•	Terminal & Editor UX
	•	Coverage vs Existing Tools
	•	What We Detect (Default vs Sanitizers)
	•	Kernel & Allocator Support
	•	Packaging & Size (Slim vs Bundled)
	•	What We Don’t Detect Yet & How to Mitigate
	•	Known Shortcomings / Risks & Mitigations
	•	Performance Targets
	•	Security & Privacy
	•	Built‑in Metrics
	•	Testing Strategy
	•	Build & Dev Environment
	•	Release Plan
	•	FAQ

⸻

Why re:compile

Traditional flows force developers (and AI agents) to juggle gdb/lldb, Valgrind, and multiple sanitizers to diagnose memory/concurrency problems. That’s slow and hard to automate. re:compile unifies this into a single compiler command and a single diagnostic format:
	•	Fast triage via eBPF + LLVM breadcrumbs (required) in a microVM: heap/resource issues, overflows via memcpy/str*, FD/socket/thread leaks, and segfault triage with near‑exact user frames.
	•	On‑demand deep dives via sanitizers/rr with the same schema and UX.
	•	Agent‑ready: MCP tools return compact, deterministic LLM‑readable JSON (with CWE, severity, confidence). An optional LLM layer can polish phrasing—grounded in facts.

⸻

High‑Level Architecture

flowchart LR
  subgraph Host
    A[recc (compiler wrapper)] -->|build| B[(Binary + Manifest)]
    B --> C{Run Mode}
    C -->|fast-triage| D[MicroVM Launcher]
    C -->|asan/ubsan/lsan| D
    C -->|tsan| D
    C -->|msan| D
    C -->|rr (native Linux)| D
    D --> E[Linux MicroVM / Native]
    E --> F[eBPF Probes (CO-RE)
      - heap_tracker
      - copy_checker
      - fd/thread trackers
      - signal/fault triage]
    E --> G[Userspace Agent
      - ringbuf consumer
      - symbolizer (DWARF)
      - bounds metadata join
      - finding builder]
    G --> H[(Findings JSON / SARIF)]
    H --> I[LSP Bridge (editor highlights)]
    H --> J[MCP Server (Cursor/Agents)]
    H --> K[Terminal Renderer]
  end

Key idea: one Finding powers terminal output, editor diagnostics, CI (SARIF), and agent tooling (MCP).

⸻

Quickstart
	1.	Build with the drop‑in wrapper recc:

recc -o build/a.out src/*.cpp   # wraps clang++/g++

	•	Injected by default: -g -fno-omit-frame-pointer -rdynamic -Wl,--export-dynamic and IR breadcrumbs (.note.ai.bounds + USDT/perf markers).

	2.	Run inside the microVM (fast triage mode):

re run ./build/a.out -- arg1 arg2
# defaults to fast-triage in Firecracker/QEMU microVM


	3.	Read findings (terminal + editor):

❌ [CWE-787] Heap overflow at foo.cpp:123
   memcpy writes 64 bytes into a 32-byte heap buffer 'buf'.
   alloc at foo.cpp:98 (makeBuf)
   hint: Bound len to capacity or allocate len bytes.


	4.	Escalate for deeper proof (same schema & UX):

re run --mode asan-ubsan-lsan ./build/a.out
re run --mode tsan ./build/a.out
re run --mode msan ./build/a.out
# Optional (native Linux):
re record ./build/a.out -- args...   # rr record
re replay <trace>                     # rr replay


	5.	Agent (Cursor) via MCP: add .cursor/mcp.json:

{
  "mcpServers": {
    "re-compile": {
      "command": "/usr/local/bin/remcp",
      "args": ["--stdio"],
      "env": { "RE_EXPLAIN": "1" }
    }
  }
}



⸻

Repository Layout

/recc/                    # CLI wrapper (Rust/C++)
/clang-pass/              # LLVM pass for bounds notes + USDT (required in fast-triage)
/runtime/
  bpf/                    # CO-RE programs: heap_tracker, copy_checker, ...
  agent/                  # ringbuf consumer + symbolizer + finding reducer
  vm/                     # microVM launcher, kernel, rootfs, BTF assets
/protocols/
  mcp/                    # MCP tool definitions + server (remcp)
  schemas/                # JSON Schema for Finding, SARIF emitters
/lsp/                     # LSP bridge (diagnostics, code lenses)
/examples/                # Deliberate-bug samples + golden outputs
/scripts/                 # Build, image pack, BTF fetch, etc.


⸻

Runtime Data Model (Findings)

Deterministic and agent‑safe; LLM polish is optional and separate.

{
  "id": "F-heap-overflow-001",
  "kind": "heap_overflow",
  "category": "vulnerability",
  "cwe": ["CWE-787"],
  "severity": "error",
  "confidence": 0.96,
  "origin": "ebpf|asan|ubsan|lsan|tsan|msan|rr",
  "primaryLocation": {
    "uri": "file:///src/foo.cpp",
    "range": {"start": {"line": 123, "character": 17}, "end": {"line": 123, "character": 41}}
  },
  "explanation": "memcpy writes 64 bytes into a 32-byte heap buffer 'buf'.",
  "explanation_llm": "(optional) At foo.cpp:123, memcpy copies 64 bytes into a 32‑byte buffer. Limit the copy or allocate len bytes.",
  "evidence": {
    "api": "memcpy",
    "len_arg": 64,
    "dest_alloc": {
      "ptr": "0x7f22c9401000",
      "size": 32,
      "allocatedAt": {"file": "file:///src/foo.cpp", "line": 98, "function": "makeBuf"}
    },
    "stacks": {
      "call": ["foo.cpp:123: memcpy", "bar.cpp:45: fill", "main.cpp:12: main"],
      "alloc": ["foo.cpp:98: makeBuf"]
    }
  },
  "codeFlow": [
    {"stage": "alloc", "location": {"file": "foo.cpp", "line": 98}},
    {"stage": "copy",  "location": {"file": "foo.cpp", "line": 123}},
    {"stage": "fault", "signal": "SIGSEGV", "address": "0x..."}
  ],
  "fixHints": [
    "Bound len <= remaining capacity.",
    "Allocate based on required length (e.g., std::vector)."
  ]
}


⸻

Compile‑Time Components

1) Compiler Wrapper (recc)
	•	Pass‑through CLI compatible with clang++/g++.
	•	Always adds: -g -fno-omit-frame-pointer -rdynamic -Wl,--export-dynamic.
	•	Generates a run manifest (binary path, DSOs, build‑id, CUs).
	•	IR breadcrumbs enabled by default (disable with --no-breadcrumbs).

2) LLVM Pass (required in fast‑triage)
	•	Emits ELF note .note.ai.bounds (globals/statics extents; optional stack arrays).
	•	Injects USDT/perf markers at risky IR patterns (pointer arithmetic on dynamic bounds, GEP with non‑const indices, wrappers around memcpy/str*).
	•	Attaches IDs so runtime events correlate with compile‑time hints.

⸻

Runtime Components

1) MicroVM Launcher
	•	Starts a Firecracker/QEMU Linux guest with BTF‑enabled kernel and minimal rootfs containing our agent + libbpf skeletons.
	•	Passes the run manifest via vsock; seccomp & no‑net by default.

2) eBPF Probe Set (CO‑RE)
	•	heap_tracker: track {ptr,size,alloc_stack,ts} for malloc/calloc/realloc and C++ operator new; validate free/delete (double/invalid/mismatch); leak summary at exit.
	•	copy_checker: on memcpy/memmove/strcpy/strncpy/strcat/sprintf/snprintf; compare requested length vs dest capacity (heap + bounds metadata) → overflow/overread/UAF.
	•	fd_tracker: live FD set via open/close/socket/accept/pipe; report leaks at exit.
	•	thread_lock_tracker: pthread_create/join (thread leaks), pthread_mutex_* heuristics (double‑lock, unlock‑without‑lock, basic lock order cycles). Heuristics only; for full race coverage, escalate to TSan.
	•	signals_faults: capture SIGSEGV/SIGABRT; correlate fault addr with nearest allocation; attach user stack.

3) Userspace Agent (inside VM)
	•	Consumes ring buffers, resolves user stacks (DWARF/BTF), and joins with compile‑time metadata.
	•	Builds Findings: root‑cause grouping; source‑exact locations; numeric evidence; CWE/severity; deterministic explanation + rule‑based fixHints.
	•	Optional SARIF output; sends findings to host via vsock/stdout.

⸻

Symbolization Requirements & Fallbacks
	•	For precise locations: build with -g -fno-omit-frame-pointer and prefer -Og/-O1 during analysis.
	•	Why frame pointers? They preserve a stable FP chain (rbp/x29) for robust unwinding; without them we fall back to DWARF CFI (slower/less reliable, esp. with inlining/LTO/stripped symbols).
	•	Stripped/LTO/inlined builds: degrade gracefully → function‑level blame or nearest frame; when no symbols, show addresses + module.
	•	Variable name recovery: DWARF location lists; if unavailable, label generically (e.g., “destination buffer”).

⸻

MicroVM & Native Modes
	•	MicroVM (default): strong isolation, uniform kernel+BTF, consistent eBPF behavior; zero host deps. Ships with our package.
	•	Native mode (--native, Linux‑only): highest environment fidelity (real drivers/filesystems). Requires host BTF and caps (CAP_BPF + CAP_PERFMON, possibly CAP_SYS_ADMIN on older kernels). If missing, we suggest microVM or provide setup guidance.
	•	rr support: rr runs on Linux; inside VMs it needs PMU virtualization (OK on KVM with PMU, generally not available on macOS HVF). Use native mode on Linux for rr.

⸻

MCP Server (Cursor/Agents)

Tools
	•	compile_run_analyze → input: { workspace, build: {args[]}, run: {argv[], env{}}, mode }; output: { findings[], logs[] }.
	•	rerun_with_mode(mode) → rebuild/re‑exec; merge + dedupe findings.
	•	explain_finding(id) → returns deterministic + optional LLM‑polished explanation and ranked fixes.
	•	set_policy → sampling/allowlists, perf guardrails.

Cursor Integration

Create .cursor/mcp.json in your repo:

{
  "mcpServers": {
    "re-compile": {
      "command": "/usr/local/bin/remcp",
      "args": ["--stdio"],
      "env": { "RE_EXPLAIN": "1" }
    }
  }
}


⸻

Escalation Path (Orchestration)
	1.	Fast triage (eBPF + LLVM breadcrumbs) → emit Findings (JSON/SARIF).
	2.	Sanitizers on demand:
	•	asan-ubsan-lsan → memory safety + UB + leaks
	•	tsan → data races
	•	msan → uninitialized reads
Findings keep the same schema, tag origin, and are unioned/deduped.
	3.	Auto‑escalation policy: if a crash has low confidence (no direct cause), we auto re‑run with ASan and merge results. We maintain a dual‑build cache (normal + ASan) keyed by build‑id to avoid repeated rebuilds.
	4.	rr (optional, Linux native): record → replay deterministically; attach locations into the same schema.

⸻

Terminal & Editor UX

CLI (deterministic + optional LLM polish via RE_EXPLAIN=1)

❌ [CWE-787][error] Heap overflow at foo.cpp:123 (id=F-heap-overflow-001)
   memcpy writes 64 bytes into a 32-byte heap buffer 'buf'.
   alloc: foo.cpp:98 (makeBuf)
   hint: Bound len to capacity or allocate len bytes (std::vector).

Editor (LSP diagnostics)
	•	source: re/ebpf|asan|tsan|msan
	•	code: RE1001..
	•	Hover shows explanation, top user frames, and fixHints.

⸻

Coverage vs Existing Tools

We do not out‑detect ASan/TSan/Valgrind/rr. Our value is orchestration + correlation + explanation across modes with one command and one schema.

Tool	Strengths	Limitations	Overhead
re:compile (fast‑triage)	Low‑overhead triage via eBPF + LLVM breadcrumbs; double/invalid free; many memcpy/str* overflows; FD/thread leaks; segfault triage; unified findings	Raw OOB on arbitrary loads/stores; uninitialized reads; true races; depends on breadcrumbs & symbols for best precision	Low
ASan (+UBSan/LSan)	Precise OOB/UAF/invalid free; many UB classes; heap leak attribution; alloc/dealloc stacks	Needs instrumented code & libs; cannot combine with TSan in one build	~2× CPU, extra RAM
TSan	Data races with happens‑before and stacks	High overhead; needs all code instrumented; cannot mix with ASan	~5–15× CPU, high RAM
MSan	Uninitialized reads with origin tracking	Strict: sanitize runtimes/deps or get noise	~3× CPU
Valgrind Memcheck	Broad memory bugs without rebuild	Very slow; struggles with custom allocators/JIT; limited concurrency insight	~10–30× CPU
rr (record/replay)	Deterministic replay; time‑travel debugging; great for flaky bugs	Linux‑only; PMU virtualization needed in VMs; not an auto‑detector	Moderate–high
gdb/lldb	Interactive debugging; stepping/expr eval	Not an automatic detector; manual workflow	N/A


⸻

What We Detect (Default vs Sanitizers)

Default (fast‑triage)
	•	Heap misuse: double/invalid free, new/delete mismatch, leak summary.
	•	Overflows/overreads through memcpy/memmove/str* (dest extent via heap + bounds metadata; UAF on dest/src if retired).
	•	FD/socket/thread leaks; pthread misuse heuristics.
	•	Segfault triage: faulting IP/address; map to nearest allocation; top user frame.

Escalation Modes
	•	asan-ubsan-lsan: Heap/stack/global OOB, UAF, invalid/double free; many UB classes; heap leak details.
	•	tsan: Data races with stacks and happens‑before info.
	•	msan: Reads of uninitialized memory (stack/heap/args/returns) with origins.

Findings carry origin and are merged/deduped.

⸻

Kernel & Allocator Support

Kernel support matrix
	•	Linux ≥ 5.10 with BTF: first‑class (CO‑RE).
	•	Older/missing BTF: use the bundled microVM kernel/BTF; native mode may be unsupported.

Allocator support
	•	Built‑in: glibc malloc/free, C++ operator new/delete (incl. sized delete).
	•	Presets: jemalloc (Phase 1–2), tcmalloc (Phase 2–3; attach symbol sets by version).
	•	Custom allocators: map symbols in config (YAML/JSON):

allocators:
  my_alloc:
    malloc: my_malloc
    free:   my_free
    realloc: my_realloc

	•	Static linking: we resolve symbols in the target binary and attach uprobes accordingly.

⸻

Packaging & Size (Slim vs Bundled)
	•	Bundled (default): includes microVM kernel+rootfs, agent, BPF, launcher.
	•	Linux: ~70–130 MB; macOS: ~100–180 MB; Windows: ~120–200 MB (compressed).
	•	Keep small with minimal musl/busybox rootfs, zstd, optional symbolizer pack.
	•	Slim: ship wrapper + agent (~15–30 MB) and fetch VM on first run (~90–140 MB). Supports delta updates and shared cache.
	•	Why larger than Valgrind (~10–20 MB)? Valgrind is a userspace tool relying on your host kernel; we ship a self‑contained microVM for uniform kernels/BTF, isolation, cross‑platform parity, and turnkey MCP/LSP integration.
	•	Controls: re vm prune to clean caches; per‑project VM sharing; optional on‑demand llvm-symbolizer download.

⸻

What We Don’t Detect Yet & How to Mitigate
	•	Raw OOB that never touches mem* → Mitigate: run ASan. Optional IR breadcrumbs help focus.
	•	Data races → Mitigate: run TSan (separate build).
	•	Uninitialized reads → Mitigate: run MSan (sanitized deps required).
	•	Deadlocks/priority inversion/starvation → Mitigate: lock‑graph heuristics (future) + targeted TSan.
	•	Logic bugs (wrong algorithm) → Mitigate: property tests/fuzzing; contracts.
	•	Uninstrumented third‑party DSOs/JIT/inline asm/MMIO in sanitizer modes → Mitigate: rebuild deps with same sanitizer; last‑resort Valgrind.
	•	GPU/accelerator memory errors (CUDA/ROCm) → Mitigate: vendor sanitizers (future integration).
	•	Heisenbugs that vanish under instrumentation → Mitigate: rr (native Linux) record/replay.

⸻

Known Shortcomings / Risks & Mitigations
	1.	eBPF visibility limits → Mitigate: mandatory LLVM breadcrumbs; focus probes on high‑leverage APIs; sanitizer escalation.
	2.	Verifier brittleness → Mitigate: keep BPF programs simple; bounded maps/loops; heavy work in userland; drop counters.
	3.	Performance overhead → Mitigate: sampling on hot paths; allowlists/denylists; publish overheads per release (fast‑triage vs ASan vs rr).
	4.	Allocator variability → Mitigate: presets for glibc/jemalloc/tcmalloc; config mapping; autodetect symbols.
	5.	Kernel drift → Mitigate: ship tested vmlinux+BTF with microVM; document native mode requirements.
	6.	Symbolization fragility → Mitigate: require -g and frame pointers for analysis runs; graceful fallback messaging.
	7.	AI hallucinations → Mitigate: ground outputs in Findings; separate facts vs hypotheses; LLM optional.
	8.	Privacy → Mitigate: redact pointers/paths before cloud LLM calls; local LLM option; explicit user API key.
	9.	Cross‑process/fork/exec → Mitigate: PID tree correlation (roadmap); document current limits.
	10.	Deadlocks → Mitigate: roadmap lock‑graph analysis; recommend targeted TSan.

⸻

Performance Targets
	•	fast‑triage: ~2–5% typical; 5–15% in memcpy‑hot loops (use sampling/allowlists).
	•	asan‑ubsan‑lsan: ≈2× runtime; memory overhead typical of ASan.
	•	tsan: 5–15× runtime; high RAM.
	•	msan: ≈3× runtime; sanitized deps required.
	•	VM startup: cold 0.3–1.2 s; warm <300 ms (prewarmed).

⸻

Security & Privacy
	•	Target binaries run jailed inside the microVM (seccomp, no network by default).
	•	Host receives only structured findings; raw memory is not exported.
	•	LLM “polish” is opt‑in via RE_EXPLAIN=1 and user‑provided API key; facts are grounded in Findings; hypotheses labelled.

⸻

Built‑in Metrics
	•	re stats → findings by class, average overheads, VM cold/warm starts.
	•	re findings --since 7d → recent issues; re vm prune to clean image caches.
	•	Metrics are stored locally by default; users can view/export them.

⸻

Testing Strategy

Unit: BPF event parsing, symbolization, bounds joins, JSON schema.

Integration: Double/invalid free, heap overflow via memcpy, FD leak, thread leak, SIGSEGV triage, lock misuse; golden Findings snapshots in CI.

E2E: re run on examples; verify terminal + LSP; orchestrate fast‑triage → ASan → TSan.

Fuzzing: finding reducer and symbolizer inputs (defend against malformed DWARF/symbols).

⸻

Build & Dev Environment
	•	LLVM/Clang (≥16), CMake, Ninja, Rust (CLI/server optional).
	•	QEMU/Firecracker; bpftool, libbpf headers; BTF kernel.
	•	MicroVM image: BTF‑enabled kernel (≥5.10), minimal rootfs with libbpf, agent, llvm-symbolizer, vsock enabled.

⸻

Release Plan

Phase 1 (Foundational)
	•	recc compiler frontend; IR breadcrumbs required.
	•	eBPF fast triage in microVM.
	•	Unified JSON/SARIF findings; LSP diagnostics.
	•	Basic LLM polish via explicit API calls (OpenAI) — grounded, optional.

Phase 2 (Incremental)
	•	One‑CLI escalation to sanitizers (ASan, UBSan, TSan, MSan).
	•	rr integration (native Linux) for nondeterministic/complex crashes.
	•	Allocator presets (glibc, jemalloc, tcmalloc incrementally).
	•	Improved symbolization (inlined frames, better column ranges).
	•	Configurable native mode (no microVM) with kernel/BTF checks.

Phase 3 (Future/Ship target)
	•	AI‑assisted static analysis: LLM summaries (ownership/nullability/contracts).
	•	LLM‑guided test generation/fuzzing (libFuzzer integration).
	•	Fine‑tuned debugging models (DebugEval‑style corpora).
	•	AI‑driven prioritization of sanitizer findings.

⸻

FAQ

Does this replace gdb/lldb?
For most memory/resource bugs, yes. For pure logic bugs or deep stepping, you can still use a debugger—our aim is you rarely need to.

Can I use this on macOS/Windows?
Yes—build with recc; runs happen in the bundled Linux microVM. Native mode is Linux‑only.

Why is the installer larger than Valgrind?
We bundle a microVM (kernel+BTF+rootfs) for isolation and consistent eBPF behavior across OSes. See Packaging & Size for Slim/Bundled options.

Will this catch every bug?
No single tool does. Fast‑triage catches many issues quickly; sanitizer/rr modes provide near‑total coverage for memory/concurrency classes, with one schema and one UX.