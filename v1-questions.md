Big, pointed questions (by area)

Correctness & coverage
	•	Allocator variance: How do we behave with non-glibc allocators (jemalloc, tcmalloc), custom C++ allocators, new/delete vs malloc/free, and aligned_alloc, posix_memalign, strdup, strndup? Are we hooking those or do we miss them?
	•	Static/PIE/stripped binaries: What’s the symbolization accuracy for stripped binaries, PIE, LTO, and fully static builds (musl)? What’s the fallback story and user guidance?
	•	Interposition vs uprobe: For builds where allocators are inlined or interposed (LD_PRELOAD, sanitizer runtimes), do our uprobes still hit the right functions? What’s the detection/migration path?
	•	C++ specifics: How do we capture exceptions/stack unwinding frames, operator new/delete array forms, placement new misuse, and destructors interacting with frees?
	•	TSan/MSan/UBSan reality check: TSan/MSan/UBSan generally require full project recompilation with specific flags; where is the boundary of “supported out-of-the-box” vs “best effort”? What’s our failure messaging when only partial instrumentation is present?
	•	Undefined behavior breadth: Which UBSan checks are enabled by default? Do we intentionally exclude noisy ones (e.g., vptr, function)? What’s the noise budget?
	•	Kernel matrix: Which kernel versions are officially supported for the eBPF fast-triage path (5.4? 5.10? 5.15? 6.x)? Do we have CI runs on at least two LTS kernels (e.g., 5.10 & 6.1) to catch verifier/regression issues?
	•	Arch matrix: AArch64 vs x86_64: are both equally exercised for uprobes offsets, symbolization paths, and sanitizer availability?

Performance & stability
	•	Overhead claim (<1% CPU): On what workloads and event rates? What’s the methodology (baseline variance, CPU pinning, perf stat counters)? Is there a published benchmark in the repo?
	•	Ringbuf backpressure: What’s the drop behavior under burst loads (alloc storms, memcpy storms)? Do we surface drops in findings/crashpack and throttle probes to avoid runaway?
	•	Map sizing & DOS: Alloc/freed maps are large. What’s the growth policy and eviction strategy? Can hostile workloads cause map pressure or trigger verifier “state too complex” paths?
	•	Watchdogs & hung tools: How do we kill stuck GDB/Valgrind/ASan jobs deterministically? Is there a single watchdog or per-tool timeouts + SIGKILL escalation and cleanup?

Security & isolation
	•	Privilege footprint: Precisely which capabilities are required in native mode (CAP_BPF? CAP_PERFMON? CAP_SYS_ADMIN?) and do we have the least-privilege path with bpf() + perf_event_open()?
	•	VM escape assumptions: What are the isolation guarantees for the microVM mode (network off? 9p/virtiofs mounts read-only?), and how do we protect the host if the target binary is hostile?
	•	Crashpack PII/code exfiltration: Crashpacks can leak paths, symbols, snippets, inputs. Do we have a redaction policy/flags (e.g., --sanitize-paths, --no-inputs)? Is there a documented data retention policy?

UX & developer flow
	•	Source mapping without compile DB: What’s the experience if compile_commands.json is missing? Is there a “best effort” mode and clearly actionable guidance to generate it (CMake export compile commands, Bear, intercept build)?
	•	Symbolization UX: Do we auto-prefer llvm-symbolizer and fall back to addr2line, with demangling and inline frames clearly marked? Is there a --no-symbolize fast mode for CI?
	•	Actionability: Do findings include direct code pointers (file:line) and short “next step” recipes? For sanitizer findings, are we post-processing to a single crisp summary (culprit frame, reason, evidence) rather than dumping raw logs?

Escalation & harnesses
	•	Repro determinism: How do we ensure harnesses reproduce flakies (seeding RNG, fixed thread counts, env vars)? If repro fails, do we auto-retry with different seeds/flags and record the matrix?
	•	Harness selection logic: When do we generate pure vs driver harness? What’s the rule table by bug kind? Is there manual override in CLI/config?
	•	Tool selection policy: Exact decision tree for ASan vs Valgrind vs TSan/MSan/UBSan/LSan. What’s the fallback order, and do we suppress redundant runs if confidence already high?

Clustering & noise control
	•	Fingerprint stability: How stable are fingerprints across builds (hash of top2 frames + ptr bucket can churn with ASLR/LTO)? Do we normalize away slide/ASLR and inline noise?
	•	Debounce & cooldown: Are the debounce windows per rule configurable via re.toml? Do we persist suppression state across runs so CI doesn’t spam?
	•	Confidence merging: What’s the precise formula when eBPF + ASan disagree? Do we always believe sanitizers? Is there a “quarantine” bucket for conflicting signals?

Packaging & platform support
	•	Mac/Windows developer story: For macOS/Windows hosts, is the VM path fully turnkey (no KVM → HVF/Hyper-V alternatives)? How are we making “run in VM” as smooth as native Linux?
	•	Binary distribution: Are we shipping static binaries/containers? Any licensing gotchas with libbpf, LLVM tools, Valgrind?
	•	Kernel headers & BTF: Do we rely on BTF on the host? What’s the fallback if BTF is missing (BTFHub/embedded BTF)? Is that documented?

Observability & ops
	•	Metrics: Do we export basic counters (events seen, drops, findings by kind, sanitizer timeouts, harness success rate)? Where do devs see them (stdout, JSON, prometheus file)?
	•	Logs: Is logging structured (level, component, correlation id)? Can users switch to verbose per component via re.toml?
	•	Crash recovery: If the agent dies mid-run, do we resume cleanly, mark partial crashpacks, and avoid zombie processes?

API/schemas & compatibility
	•	Schema versioning: You note v1. What’s the migration plan to v2 (deprecations, changelog, upconverters)?
	•	Backwards compatibility: Will existing CI scripts using today’s re-findings.log keep working? What’s the communicated EOL window?

⸻

Specific follow-ups from the docs & your summary
	•	TSan/MSan support: The README claims support for TSan/MSan/UBSan/LSan. Where’s the exact build flag matrix and the requirement to recompile targets? Is QUICKSTART explicit about “runtime vs full recompile” expectations?
	•	QUICKSTART reproducibility: QUICKSTART shows easy paths to run; does it include the “generate compile_commands” step and “no symbols” fallback narrative?
	•	CHANGELOG accuracy: The perf claim and “complete test coverage” are strong—do we have links to benchmark suites and test coverage reports (even if textual)?
	•	ARCHITECTURE invariants: Is there a diagram for dataflow state machines (ringbuf producer/consumer, escalation scheduler, harness builder) with failure states and retries? The doc is descriptive, but do we codify invariants (e.g., “no sanitizer runs before ARMED flag,” “no harness without stable fingerprint”)?

⸻

What I think might still be missing (or under-specified)
	1.	Allocator & API surface completeness
	•	Hook set for str*dup, *memalign, C++ new/delete variants, operator new(nothrow), sized delete, and reallocarray. If already done, document it clearly.
	2.	Hard kernel/arch support table
	•	A short table: {kernel version, arch} × {status, known quirks}. This becomes gold for users and for triage.
	3.	Noise guardrails
	•	Default debounce/cooldown values per rule in re.toml with a clear “why.” A “safe defaults” section in README.
	4.	Harness determinism kit
	•	A tiny helper lib linked into harnesses to fix seeds, set env, pin threads/affinity, and optionally “delay” to surface races with TSan.
	5.	Sanitizer orchestration truth table
	•	One page mapping “bug kind → tools to run → expected signal → success criteria → time budget.”
	6.	Security posture page
	•	Minimal caps, VM isolation model, PII redaction toggles, and a threat model paragraph.
	7.	Metrics/health
	•	Emit a health.json inside crashpack with counters + timing + versions, and a --metrics flag to print a one-line summary at the end of runs.
	8.	CI reference pipeline
	•	A ready-to-copy GitHub Actions workflow (and a GitLab one) that runs native on Linux and falls back to VM for macOS/Windows.
	9.	Licensing disclosures
	•	A short LICENSES.md clarifying libbpf, LLVM tools, Valgrind, and any redistribution boundaries.
	10.	BTF fallback

	•	If you plan to support older kernels or containers, decide on BTFHub/embedded BTF now (or explicitly state “requires kernel with vmlinux BTF”).

⸻

Finalization questions to lock scope
	•	Single source of truth: Is re_events.h the canonical schema, and are all downstream crates generated or validated against it (e.g., via build script + JSON schema tests)?
	•	CLI contract: Is rerun the single entry point (“rerun run” does fast-triage, clustering, and conditional escalation; “rerun escalate” for manual)? Do we freeze this now?
	•	Default mode per platform: Linux default = native; macOS/Windows default = VM. Confirm?
	•	Fail-closed vs fail-open: If symbolizer or compile DB is missing, do we continue with degraded UX or abort with actionable error? Pick one default and document it.
	•	Telemetry (opt-in?): Are we collecting anonymous usage metrics? If yes, provide a clear toggle and a data doc. If no, say so.
