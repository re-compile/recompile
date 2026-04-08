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

### `re-harness/`

Harness generation utilities.

This is not the current blocker, but it should continue consuming the same canonical crashpack inputs.

### `re-rules/`

Shared config/types plus symbolization support used by the broader pipeline.

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

Escalation should use provenance first.

## Environment Requirements

Supported environments:

- Linux host, or
- Docker with `--privileged --pid=host`

Why the PID namespace matters:

- `rerun` filters findings to the launched target PID
- BPF events use the kernel-visible PID
- without `--pid=host`, those can diverge in Docker and valid events get dropped

## Current Priorities

Phase 0 is complete.

Current Phase 1 priorities:

1. keep the supported Docker-native path obvious and repeatable
2. add a repeatable regression path for the three goldens
3. remove remaining warning-level stale code in active crates
4. polish symbolization only where it materially improves user-visible findings
