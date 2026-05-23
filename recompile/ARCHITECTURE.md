# Architecture

## Supported Flow

`re:compile` is currently a Linux-native runtime analysis pipeline.

Supported execution path:

```text
Target ELF binary
  -> rerun observe
  -> per-target rerun run --native plumbing
  -> paused post-exec target attach
  -> re-mini (C runtime agent)
  -> eBPF uprobes on libc allocation/copy functions
  -> event normalization
  -> findings.json + crashpack artifacts
  -> dependencies.json + issue-groups.json
  -> evidence-pack.json
  -> observe-level escalation policy
  -> escalations/results.json + raw tool logs + parsed tool report
  -> run-summary.json
  -> optional rerun summarize <crashpack> --format json
  -> optional rerun replay <crashpack> --format json
```

The current release path is Docker-native or Linux-host-native. VM mode is deferred.

## Main Components

### `rerun/`

Top-level CLI and native orchestration.

Responsibilities:

- launch the target in a stopped post-exec state
- start and stop the agent
- normalize findings into canonical `findings.json`
- assemble crashpack metadata and binary artifacts
- invoke escalation and crashpack commands against the canonical output
- write observation-run summaries through `rerun observe`
- emit agent summaries and minimal replay results from crashpack artifacts

### `runtime/agent/re-mini.c`

Current runtime source of truth.

Responsibilities:

- load BPF objects
- attach uprobes to `malloc`, `calloc`, `realloc`, `free`, `memcpy`, `memmove`,
  `memset`, scoped `strcpy`, and scoped `strncpy`
- filter to the target process
- snapshot module mappings for short-lived processes
- symbolize stack frames when possible
- emit v1 findings and debug lines

### `runtime/bpf/`

BPF programs used by the native runtime.

Current important objects:

- `heap_tracker.bpf.c`
- `copy_checker.bpf.c`

`sentinel_extra.bpf.c` is optional and not part of the current MVP gate.

### `re-crashpack/`

Helpers for canonical findings, manifests, and captured binary metadata.

### `re-escalate/`

Escalation adapters.

Current expectation:

- consume explicit finding provenance
- avoid guessing paths from example names or finding classes
- write structured escalation results with command, exit status, raw output paths, parsed report path, and detected classes
- support explicit binary scans for no-finding crashpacks without inventing a synthetic finding

Current implemented adapters:

- `valgrind` for existing binaries in crashpacks and explicit binary scans
- `asan` for binaries that were already compiled with `-fsanitize=address`
- `lsan` for binaries that were already compiled with `-fsanitize=leak`
- `ubsan` for binaries that were already compiled with `-fsanitize=undefined`

Sanitizer adapters do not run against ordinary binaries and do not rebuild
source files implicitly. If the crashpack binary does not contain the requested
sanitizer instrumentation, the adapter returns a structured failure explaining
the required compile flag.

### `re-rules/`

Shared config/types plus symbolization support used by the broader pipeline.

The active finding engine is `runtime/agent/re-mini.c`; stale rule-engine demos
are not part of the supported runtime path.

### `recc/` and `llvm-passes/`

Optional compiler-wrapper and compiler-pass experiments.

Current decision:

- `recc` remains an advanced optional path
- `recc` is not required for `rerun run --native <binary>`
- LLVM pass building is validated by `make recc-smoke`, not by the native MVP or Phase 2 gates
- implicit pass injection is deferred until the pass ABI and compiler version contract are stable

## Contracts

### Canonical persisted contract

- `findings.json`
- JSON array
- source of truth for downstream tools

### Agent evidence contract

- `evidence-pack.json`
- JSON object
- deterministic, agent-readable summary built from canonical crashpack artifacts
- includes artifact pointers, binary provenance, class counts, source resolution counts, and compact per-finding evidence
- does not replace `findings.json`

`rerun summarize <crashpack> --format json` reads this evidence pack plus
optional `escalations/results.json` and emits the compact agent summary used by
coding agents.

`rerun replay <crashpack> --format json` re-executes the recorded binary and
arguments from `analysis.json`, applies the recorded cwd when present, and
prefers the captured binary under `bins/`. It writes `replay/results.json`.
This is a minimal repro contract, not full input/environment replay.

### Observation-run contract

- `run-summary.json`
- JSON object
- source of truth for a local observation run
- links one or more target crashpacks
- records target status, finding totals, escalation state, dependency metadata
  paths, issue group counts, and next inspection commands

`rerun observe <binary>` is the current default entry point. It supports a
single binary per invocation, args after `--`, `--cwd`, `--output`,
`--timeout-ms`, `--native-only`, and `--deep`.

Default observe policy runs native first and asks Valgrind to confirm only when
native findings exist. Deep observe policy additionally asks Valgrind to scan
clean native runs and asks ASan to scan only when the binary is already
ASan-instrumented.

### Debug contract

- `re-findings.jsonl`
- `RE:FINDING:` lines
- useful for inspection, not canonical input

### Provenance

Findings can include explicit provenance for:

- analyzed binary path
- original binary path
- source path when available
- source resolution status

Escalation should use provenance first.

## Environment Requirements

Supported environments:

- Linux host, or
- Docker with `--privileged --pid=host`

Why the PID namespace matters:

- `rerun` filters findings to the launched target PID
- BPF events use the kernel-visible PID
- without `--pid=host`, those can diverge in Docker and valid events get dropped

## Phase Status

Phase 0 is complete.
Phase 1 is complete for the Linux-native MVP scope.
Phase 2 is complete for the current issue-backed escalation and evaluation scope.
Phase 3 is complete for the agentic runtime evidence MVP scope.
Phase 4 is complete for the local runtime observability foundation.

The Phase 1 release gate is:

```bash
make rc
```

This runs active Rust checks/tests, the three golden regressions, and user-style finding/no-finding samples.

The current closeout gate is:

```bash
make phase4
```

`make phase4` runs the Phase 2 gate, observe smoke tests, project-shaped
fixtures, observation hit-rate scoring, lower-level hit-rate scoring, and
optional `recc` wiring validation. `recc` remains optional because it is not
part of the primary native runtime workflow.

Post-Phase-4 candidates:

1. grow memory/resource coverage without changing the observation contract
2. add already-instrumented sanitizer adapters for UBSan/TSan/MSan/LSan
3. add native resource lifecycle tracing where feasible
4. add repeated-run and `rr`-backed nondeterminism evidence
5. improve symbolization and source narratives beyond primary user frames
6. capture richer replay inputs/environment when real workflows require it
7. revisit optional `recc`/LLVM pass integration only if a concrete user workflow needs it

## Evaluation

`make hit-rate` runs the current user-style corpus through native analysis and
Valgrind escalation, then writes `build/hit-rate/summary.json`.

The summary records:

- expected native and escalation class per sample
- native finding classes and TP/TN/FP/FN outcome
- native source resolution statuses
- escalation detected classes and TP/TN/FP/FN outcome
- unsupported native classes when a bug class is intentionally Valgrind-first
- output directory per case

Current Valgrind-first classes:

- `use_after_free`
- `memory_leak`

Current native heap-write coverage:

- `memcpy`
- `memmove`
- `memset`
- scoped `strcpy`
- scoped `strncpy`

Current native allocator tracking:

- `malloc`
- `calloc`
- `realloc`
- `posix_memalign`
- `aligned_alloc`
- bounded `strdup` inputs
- C++ `operator new` / `operator new[]`
- C++ `operator delete` / `operator delete[]`

Current native resource lifecycle coverage:

- libc `open`, `open64`, `openat`, `openat64`, and `creat`
- libc `close`
- `fd_leak` by draining still-open fd records when the target exits
- `double_close` for descriptors tracked as opened and then closed already
- `invalid_close` for failed close calls on descriptors that were never tracked

`realloc` tracking preserves the old allocation on failed non-zero resize,
marks the old allocation freed on successful moves, and treats
`realloc(ptr, 0)` as freeing `ptr` when libc returns `NULL`. Bounded `strdup`
inputs are tracked by the copied string length; oversized strings are recorded
as unknown capacity to avoid false overflow findings from truncated BPF reads.
`strdup` findings can still have unresolved source provenance when the observed
allocation stack does not unwind back into user code.

C++ allocator-family tracking attaches to libstdc++ operator symbols `_Znwm`,
`_Znam`, `_ZdlPv`, `_ZdlPvm`, `_ZdaPv`, and `_ZdaPvm` when libstdc++ is
available on the Linux host or Docker image. Native findings use
`allocator_mismatch` for `new/free`, `malloc/delete`, `new[]/delete`, and
`new/delete[]`, and include both `alloc_family` and `dealloc_family` in
`evidence.memory`. The MVP intentionally does not claim coverage for custom
overloaded C++ operators, placement new/delete, nothrow operators, or aligned
C++17 allocation overloads.

Fd lifecycle tracking is intentionally first-pass and descriptor-centric. It
does not yet model `dup`, `dup2`, `dup3`, `fcntl(F_DUPFD*)`, socket creation,
`accept`, pipe ownership, fork/exec inheritance, or intentional fd handoff to
another owner. `fd_leak` is Valgrind-confirmable in escalation; `double_close`
and `invalid_close` are currently native-only and appear as unsupported for
tool-backed confirmation in hit-rate. `invalid_close` can retain only a
binary-offset action stack when the target exits before full user-source
symbolization completes.

Deferred native string-copy coverage:

- `strcat`
- `strncat`

## Source Quality

Native findings attach `provenance.source_status`:

- `resolved` when a concrete source path is available
- `unresolved` when source lookup fails without guessing

Source resolution prefers explicit runtime source data, then stack summaries,
then debug-info lookup from binary-offset stack frames.
