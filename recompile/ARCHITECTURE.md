# Architecture

## Supported Flow

`re:compile` is currently a Linux-native runtime analysis pipeline.

Supported execution path:

```text
Target ELF binary
  -> rerun run --native
  -> paused post-exec target attach
  -> re-mini (C runtime agent)
  -> eBPF uprobes on libc allocation/copy functions
  -> event normalization
  -> findings.json + crashpack artifacts
  -> optional rerun escalate <crashpack> --tool valgrind
  -> optional rerun escalate <crashpack-without-findings> --tool valgrind --scan-binary
  -> optional rerun escalate <asan-built-crashpack> --tool asan --scan-binary
  -> escalations/results.json + raw tool logs + parsed tool report
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

### `runtime/agent/re-mini.c`

Current runtime source of truth.

Responsibilities:

- load BPF objects
- attach uprobes to `malloc`, `calloc`, `realloc`, `free`, and `memcpy`
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

Current implemented adapter:

- `valgrind` for existing binaries in crashpacks and explicit binary scans
- `asan` for binaries that were already compiled with `-fsanitize=address`

ASan does not run against ordinary binaries and does not rebuild source files
implicitly. If the crashpack binary does not contain ASan instrumentation,
the adapter returns a structured failure explaining the `-fsanitize=address`
requirement.

### `re-harness/`

Harness generation utilities.

This is not the current blocker, but it should continue consuming the same canonical crashpack inputs.

### `re-rules/`

Shared config/types plus symbolization support used by the broader pipeline.

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

The current release gate is:

```bash
make rc
```

This runs active Rust checks/tests, the three golden regressions, and user-style finding/no-finding samples.

Current Phase 2 candidates:

1. grow the hit-rate corpus as new bug classes land
2. broaden ASan-backed coverage beyond the first already-instrumented smoke
3. improve symbolization beyond primary user frames
4. add broader clean-negative and real-world user-binary regressions
5. keep optional `recc`/LLVM pass wiring separate from the primary native flow

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
- `fd_leak`

## Source Quality

Native findings attach `provenance.source_status`:

- `resolved` when a concrete source path is available
- `unresolved` when source lookup fails without guessing

Source resolution prefers explicit runtime source data, then stack summaries,
then debug-info lookup from binary-offset stack frames.
