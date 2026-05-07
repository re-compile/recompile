# re:compile Workspace

This directory contains the active `re:compile` workspace.

The current supported workflow is Linux-native analysis of C/C++ binaries using `rerun` and the C eBPF agent.

## Current State

Phase 0 is complete on the supported Docker-native path.
Phase 1 is complete for the Linux-native MVP scope.
Phase 2 is complete for the current issue-backed escalation and evaluation scope.
Phase 3 is complete for the agentic runtime evidence MVP scope.
Phase 4 is in progress; `rerun observe` is the new observation-run entry point.

What is working now:

- `rerun run --native <binary>` is the primary execution path
- `rerun observe <binary>` writes `.re/run-summary.json` plus per-target crashpack artifacts
- findings persist canonically to `findings.json`
- agent-readable evidence persists to `evidence-pack.json`
- debug/streaming output goes to `re-findings.jsonl`
- crashpack and escalation consume explicit provenance instead of guessing from example names
- Valgrind escalation can confirm a finding from an existing crashpack
- ASan escalation can confirm an already-ASan-built binary from an existing crashpack
- `rerun summarize <crashpack> --format json` emits compact agent summaries
- `rerun replay <crashpack> --format json` replays the recorded command with the captured binary when present
- multiple independent findings in one process are preserved through key-based dedupe
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
- `evidence-pack.json` is the agent-readable summary of a crashpack
- `re-findings.jsonl` and `RE:FINDING:` lines are debug streams only
- the current runtime source of truth is `runtime/agent/re-mini.c`
- VM mode, macOS-first development, and the Rust agent are deferred

## Commands

### Analyze a binary

```bash
cargo run -p rerun -- run --native build/examples/invalid_free --output build/invalid-free
```

Primary outputs:

- `build/invalid-free/findings.json` - canonical finding array
- `build/invalid-free/evidence-pack.json` - compact evidence pack for coding agents
- `build/invalid-free/manifest.json` - crashpack metadata
- `build/invalid-free/re-findings.jsonl` - debug stream

### Observe a binary

```bash
cargo run -p rerun -- observe build/user-samples/copy_overrun_case --output build/observe-demo
jq . build/observe-demo/run-summary.json
```

`observe` is the Phase 4 local observability entry point. It currently runs the
native crashpack path, writes `.re`-style run summaries, supports `--cwd`,
`--timeout-ms`, `--native-only`, and target args after `--`. Observe-level
automatic escalation is tracked separately for Phase 4.

Primary outputs:

- `build/observe-demo/run-summary.json` - run-level observation summary
- `build/observe-demo/targets/copy_overrun_case/findings.json` - target findings
- `build/observe-demo/targets/copy_overrun_case/evidence-pack.json` - target evidence pack
- `build/observe-demo/targets/copy_overrun_case/analysis.json` - target run metadata

### Escalate an existing crashpack

```bash
cargo run -p rerun -- escalate build/invalid-free --tool valgrind
jq . build/invalid-free/escalations/results.json
```

### Summarize for coding agents

```bash
cargo run -p rerun -- summarize build/invalid-free --format json
```

This reads `evidence-pack.json` plus optional `escalations/results.json` and
prints a compact deterministic JSON summary.

### Replay a crashpack

```bash
cargo run -p rerun -- replay build/invalid-free --format json
```

This re-executes the recorded binary with args from `analysis.json`, preferring
the captured binary under `bins/` when present, and writes `replay/results.json`.

### Validate a crashpack

```bash
cargo run -p rerun -- crashpack validate build/invalid-free
```

### Run the Phase 1 RC gate

```bash
make rc
```

This runs active Rust checks/tests, the golden baseline, and user-style external samples.

### Run the current closeout gates

```bash
make phase2
make observe-smoke
make hit-rate
make recc-smoke
```

`make phase2` runs the RC gate, Valgrind escalation smoke, ASan binary smoke,
agent summary smoke, and replay smoke. `make observe-smoke` validates the Phase
4 observation-run MVP against one clean and one finding binary. `make hit-rate`
records native and escalation outcomes for the current user-style corpus. `make
recc-smoke` validates optional compiler-wrapper wiring outside the primary
runtime path.

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

### Validate ASan escalation

```bash
make asan-smoke
```

ASan validation uses binaries built under `build/user-samples-asan/`. This is
deliberate: ASan only applies when the target was compiled with
`-fsanitize=address`.

### Validate optional recc wiring

```bash
make recc-smoke
```

This checks the optional compiler-wrapper path and LLVM pass build. It does not
replace `rerun run --native`, and it is intentionally not part of `make phase2`.

### Score hit rate

```bash
make hit-rate
jq . build/hit-rate/summary.json
```

The current corpus includes native-confirmed heap/double/invalid-free cases,
clean negatives, and Valgrind-first `use_after_free`, `memory_leak`, and
`fd_leak` cases.

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

To run ASan on a no-finding crashpack, use an ASan-instrumented target:

```bash
./scripts/build-user-samples.sh
./target/release/rerun run --native build/user-samples-asan/use_after_free_case --output build/asan-demo
./target/release/rerun escalate build/asan-demo --tool asan --scan-binary
jq . build/asan-demo/escalations/results.json
```

Running `--tool asan` on a normal binary is rejected with an explicit
`-fsanitize=address` build requirement.

## Active Components

- `rerun/` - native CLI/orchestration
- `runtime/agent/re-mini.c` - C agent
- `runtime/bpf/` - BPF programs
- `re-crashpack/` - findings/manifests/binary metadata helpers
- `re-escalate/` - escalation adapters
- `re-rules/` - shared config/types/symbolization support; not the active finding engine
- `recc/` - optional compiler wrapper; not required for the native MVP path
- `llvm-passes/` - optional compiler pass experiments; not required for native runtime analysis

## Docs

- [`QUICKSTART.md`](QUICKSTART.md)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
