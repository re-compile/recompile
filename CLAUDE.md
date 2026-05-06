# CLAUDE.md - Assistant Context for re:compile

This document gives coding agents the current project shape. The canonical public docs are `README.md`, `recompile/README.md`, and `recompile/ARCHITECTURE.md`.

## Current Direction

`re:compile` is a Linux-native runtime evidence tool for C/C++ memory debugging.

The supported path is:

1. build or provide a Linux ELF binary
2. run `rerun run --native <binary> --output <crashpack>`
3. collect native eBPF findings from the C runtime agent
4. inspect canonical `findings.json`
5. optionally run `rerun escalate <crashpack> --tool valgrind|asan`

VM mode, macOS-first support, the Rust runtime agent, and required `recc` workflows are deferred.

## Active Components

| Component | Location | Status |
|-----------|----------|--------|
| CLI/orchestration | `recompile/rerun/` | Active |
| C runtime agent | `recompile/runtime/agent/re-mini.c` | Active finding engine |
| BPF programs | `recompile/runtime/bpf/heap_tracker.bpf.c`, `copy_checker.bpf.c` | Active |
| Shared event schema | `recompile/runtime/shared/re_events.h` | Active |
| Crashpack types/metadata | `recompile/re-crashpack/` | Active helper crate |
| Escalation adapters | `recompile/re-escalate/` | Active for Valgrind and already-ASan-built binaries |
| Rules/symbolization helpers | `recompile/re-rules/` | Shared helper crate; not the active finding engine |
| Compiler wrapper | `recompile/recc/` | Optional compile-wrapper smoke only |
| LLVM pass | `recompile/llvm-passes/` | Optional wiring smoke only |

## Validation Commands

Run inside the supported Docker-native environment:

```bash
cd /workspace/recompile/recompile
make rc
make phase2
make hit-rate
make recc-smoke
cargo test --workspace --all-targets
```

Docker-native tracing requires `--privileged --pid=host`.

## Important Constraints

- Runtime analysis only observes executed paths.
- Native eBPF currently detects heap overflow, double free, and invalid free on the active path.
- Use-after-free, memory leak, and file descriptor leak are currently Valgrind-first.
- ASan escalation only works for binaries already built with `-fsanitize=address`.
- Generated `runtime/bpf/vmlinux.h` is required for BPF builds but must remain ignored and regenerated locally.
- `recc` compiles and writes optional manifest metadata; it does not produce crashpacks or run analysis.

## Phase 3 Direction

Phase 3 is agentic runtime evidence:

- remove misleading stale surfaces
- preserve multiple independent findings per run
- add agent-readable evidence output
- add summarize/replay workflow where feasible
- keep all outputs honest about observed runtime coverage
