# Deferred Components

This document keeps optional and deferred code from being confused with the supported OSS path.

## Supported Happy Path

The current user-facing path is:

```bash
rerun observe <linux-elf-binary> --output <dir>
```

`observe` orchestrates native runtime analysis, crashpack artifact writing, optional escalation, run summaries, issue groups, dependency metadata, and agent-readable evidence packs. `rerun run --native <binary>` remains the lower-level per-target primitive used by `observe`.

## Component Status

| Component | Status | Notes |
| --- | --- | --- |
| `rerun/` | Active | Primary CLI and orchestration for `observe`, native runs, escalation, summarize, replay, and crashpack validation. |
| `runtime/agent/re-mini.c` | Active | Current native runtime detector and symbolization source of truth. |
| `runtime/bpf/` | Active | eBPF uprobes used by the native runtime detector. |
| `re-escalate/` | Active | Valgrind, ASan, LSan, UBSan, and GDB adapters. Sanitizers require already-instrumented binaries. |
| `re-crashpack/` | Active library | Shared artifact types and writer helpers used by `rerun`; not a standalone user-facing generator. |
| `schemas/` | Active contracts | JSON schemas for persisted findings, evidence packs, and observation summaries. |
| `re-rules/` | Deferred/internal | Rule-engine primitives and symbolization support kept for future experiments. It is not the active finding engine. |
| `recc/` | Optional/deferred | Compile-only wrapper smoke-tested by explicit `make recc-smoke`; not required for `observe` and not part of phase gates. |
| `llvm-passes/` | Optional/deferred | Compiler-pass experiment built only by explicit `make recc-smoke`/`make passes`; no implicit pass injection. |
| VM launch flow | Deferred | Linux-native host or Docker-native execution is the supported path. |
| Rust runtime agent | Deferred | The C runtime agent is the supported detector. |

## Validation Boundary

`make phase6` is the current aggregate validation gate for the supported runtime path. It runs the Phase 5 gate plus deterministic repeated-run fixtures. It intentionally excludes optional `recc`/LLVM validation. Use `make recc-smoke` only when intentionally working on that optional path.

`make phase5-closeout-smoke` scans active production paths for sample-specific, golden-specific, hotfix-like, and stale RECC-era labels. Deferred components are documented here rather than treated as production detector code.
