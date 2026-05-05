# re:compile Workspace

This directory contains the active `re:compile` workspace.

The current supported workflow is Linux-native analysis of C/C++ binaries using `rerun` and the C eBPF agent.

## Current State

Phase 0 is complete on the supported Docker-native path.
Phase 1 is complete for the Linux-native MVP scope.

What is working now:

- `rerun run --native <binary>` is the primary execution path
- findings persist canonically to `findings.json`
- debug/streaming output goes to `re-findings.jsonl`
- crashpack and escalation consume explicit provenance instead of guessing from example names
- Valgrind escalation can confirm a finding from an existing crashpack
- the three goldens validate in Docker with `--privileged --pid=host`

Validated goldens:

- `memcpy_overflow` -> `heap_overflow`
- `double_free` -> `double_free`
- `invalid_free` -> `invalid_free`

## Supported Workflow

Run from `recompile/`.

### Docker-native

```bash
docker build -t recompile-bootstrap:host ..
docker run --rm -it --privileged --pid=host \
  -v "$PWD/..":/workspace/recompile \
  recompile-bootstrap:host bash
```

Inside the container:

```bash
cd /workspace/recompile/recompile
make rc
```

### Native Linux host

```bash
cargo build --release -p rerun
./scripts/build-examples.sh
./target/release/rerun run --native build/examples/double_free --output build/demo
```

## Important Constraints

- Docker-native tracing requires `--privileged --pid=host`
- `findings.json` is the canonical persisted output
- `re-findings.jsonl` and `RE:FINDING:` lines are debug streams only
- the current runtime source of truth is `runtime/agent/re-mini.c`
- VM mode, macOS-first development, and the Rust agent are deferred

## Commands

### Analyze a binary

```bash
cargo run -p rerun -- run --native build/examples/invalid_free --output build/invalid-free
```

### Escalate an existing crashpack

```bash
cargo run -p rerun -- escalate build/invalid-free --tool valgrind
jq . build/invalid-free/escalations/results.json
```

### Validate a crashpack

```bash
cargo run -p rerun -- crashpack validate build/invalid-free
```

### Run the Phase 1 RC gate

```bash
make rc
```

This runs active Rust checks/tests, the golden baseline, and user-style external samples.

### Run the golden-only baseline

```bash
./scripts/validate-phase1.sh
```

Or:

```bash
make phase1
```

### Validate user-style binaries

```bash
make external-smoke
```

### Validate Valgrind escalation

```bash
make escalation-smoke
```

For one external binary:

```bash
./scripts/validate-binary.sh --binary ./my_test --expect-class heap_overflow
```

For one binary that should be clean:

```bash
./scripts/validate-binary.sh --binary ./my_test --expect-none
```

To inspect the no-finding diagnostics on a clean sample:

```bash
./scripts/build-user-samples.sh
./target/release/rerun run --native build/user-samples/clean_bounded_memcpy --output build/clean-demo
```

## Active Components

- `rerun/` - native CLI/orchestration
- `runtime/agent/re-mini.c` - C agent
- `runtime/bpf/` - BPF programs
- `re-crashpack/` - findings/manifests/binary metadata helpers
- `re-escalate/` - escalation adapters
- `re-harness/` - repro harness generation
- `re-rules/` - shared config/types/symbolization support

## Docs

- [`QUICKSTART.md`](QUICKSTART.md)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`../ROADMAP.md`](../ROADMAP.md)
- [`../ISSUES_DISCUSSION.md`](../ISSUES_DISCUSSION.md)
