# RECC Sentinel Architecture

## Current Scope

RECC Sentinel is currently a Linux-native runtime analysis toolchain.

The supported path is:
- build or provide a Linux ELF binary
- run `rerun --native`
- attach the C `re-mini` agent to libc allocation/copy functions
- persist canonical findings to `findings.json`
- keep streaming/debug output in `re-findings.jsonl`

VM mode still exists in the repo, but it is deferred and not part of the primary workflow.

## Primary Flow

```text
Target Binary
  -> rerun --native
  -> re-mini (C agent)
  -> eBPF uprobes on malloc/calloc/realloc/free/memcpy
  -> ring buffer events
  -> finding normalization
  -> findings.json + crashpack artifacts
```

## Main Components

### `rerun/`

Top-level CLI.

Current responsibilities:
- native execution orchestration
- paused-target launch so probes attach before user code runs
- canonical findings normalization into `findings.json`
- crashpack manifest/binary artifact generation

### `runtime/agent/re-mini.c`

Current runtime source of truth.

Responsibilities:
- load BPF objects
- attach uprobes to libc functions
- filter events to the target process
- symbolize stack frames when possible
- emit `RE:FINDING:` debug lines
- write v1 findings used by the native crashpack flow

### `runtime/bpf/`

Current BPF programs.

Important objects:
- `heap_tracker.bpf.c`
- `copy_checker.bpf.c`
- `sentinel_extra.bpf.c` is optional and not part of the Linux-native MVP path

### `re-rules/`

Shared configuration and rule-engine logic.

Current role in the repo:
- config/types support
- symbolizer support
- rule-engine groundwork

### `re-escalate/`

Escalation adapters.

Current state:
- library and CLI shape exist
- plumbing is still being stabilized around the native findings contract
- not yet the release gate for the Linux-native MVP

### `re-crashpack/`

Crashpack helpers for findings/manifests/binary metadata.

Current expectation:
- consume canonical `findings.json`
- avoid relying on debug-stream formats as primary input

### `re-harness/`

Harness generation utilities.

Current state:
- CLI/library exist
- not the current blocker
- should consume the same canonical crashpack inputs as the rest of the pipeline

## Contracts

### Canonical persisted output
- `findings.json`
- JSON array
- this is the source of truth for downstream tools

### Debug/streaming output
- `re-findings.jsonl`
- `RE:FINDING:` lines
- useful for inspection, not the canonical persisted contract

## Supported Development Environment

Primary supported environment:
- Linux host, or
- Docker with `--privileged --pid=host`

Important constraint:
- native eBPF tracing in Docker must share the host PID namespace
- otherwise the target PID seen by `rerun` and the kernel-visible PID seen by BPF can diverge

## Near-Term Priorities

1. keep the native Linux path deterministic
2. remove remaining example-specific plumbing
3. finish crashpack/escalation integration against canonical findings
4. improve symbolization quality
5. keep docs aligned with the actual supported workflow
