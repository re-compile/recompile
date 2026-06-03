# re:compile Workspace

This directory contains the active `re:compile` workspace.

The current supported workflow is Linux-native analysis of C/C++ binaries using `rerun` and the C eBPF agent.

## Current State

Phase 0 is complete on the supported Docker-native path.
Phase 1 is complete for the Linux-native MVP scope.
Phase 2 is complete for the current issue-backed escalation and evaluation scope.
Phase 3 is complete for the agentic runtime evidence MVP scope.
Phase 4 is complete for the local runtime observability foundation.
Phase 5 is complete for the current memory/resource coverage expansion scope.
`rerun observe` is the primary human/agent observation-run entry point.

What is working now:

- `rerun observe <binary>` is the primary human/agent entry point
- `rerun run --native <binary>` is the lower-level native execution path used per target
- `rerun observe` supports args, `--cwd`, timeouts, native-only mode, deep escalation mode, and opt-in repeated runs
- findings persist canonically to `findings.json`
- agent-readable evidence persists to `evidence-pack.json`
- binary and dynamic dependency metadata persists to `dependencies.json`
- stable fingerprints and issue groups persist to `issue-groups.json`
- debug/streaming output goes to `re-findings.jsonl`
- crashpack and escalation consume explicit provenance instead of guessing from example names
- Valgrind escalation can confirm a finding from an existing crashpack
- ASan escalation can confirm an already-ASan-built binary from an existing crashpack
- `rerun summarize <crashpack> --format json` emits compact agent summaries
- `rerun replay <crashpack> --format json` replays the recorded command with the captured binary and recorded cwd when present
- multiple independent findings in one process are preserved through key-based dedupe
- project-style fixtures validate multi-file, args/cwd, multi-binary, shared-library, timeout, and Valgrind-first paths
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

For the full current closeout gate:

```bash
make phase5
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
- `dependencies.json` records binary identity, ELF metadata, and dynamic dependency resolution status
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
- `build/invalid-free/dependencies.json` - binary and dynamic dependency metadata
- `build/invalid-free/issue-groups.json` - stable finding fingerprints and grouped issues
- `build/invalid-free/manifest.json` - crashpack metadata
- `build/invalid-free/re-findings.jsonl` - debug stream

### Observe a binary

```bash
cargo run -p rerun -- observe build/user-samples/copy_overrun_case --output build/observe-demo
jq . build/observe-demo/run-summary.json
```

`observe` is the Phase 4 local observability entry point. It runs the native
crashpack path, writes `.re`-style run summaries, supports `--cwd`,
`--timeout-ms`, `--native-only`, `--deep`, `--repeat`, and target args after
`--`.

Default observe behavior runs Valgrind confirmation when native findings exist.
`--deep` runs a Valgrind binary scan even when native is clean. If the binary is
already sanitizer-instrumented, `observe` records the Valgrind clean scan as
`skipped` and uses ASan, LSan, or UBSan scans as the primary deep evidence path.

`observe` also reports native tracing capabilities in
`run-summary.json.targets[].diagnostics`. In restricted agent sandboxes where
Linux eBPF tracing cannot start because BPF, BTF, ptrace, PID namespace,
privilege, or native agent artifacts are unavailable, default observe creates a
minimal crashpack and attempts a tool-only fallback. The default fallback runs a
whole-binary Valgrind scan; `--deep` also attempts ASan, LSan, and UBSan scans
when applicable. For sanitizer-built binaries, deep fallback records the
Valgrind scan as `skipped` instead of silently omitting it. `--native-only`
disables this fallback and preserves strict native-tracing failure behavior.

Repeated observation is opt-in:

```bash
cargo run -p rerun -- observe --repeat 3 --native-only build/user-samples/clean_malloc_free --output build/repeat-demo
jq . build/repeat-demo/run-summary.json
```

Repeat mode writes each attempt under
`build/repeat-demo/attempts/000N/` and writes an aggregate
`build/repeat-demo/run-summary.json` with attempt-prefixed target names.
`--repeat --deep` is intentionally rejected until the repeat escalation policy
is implemented, because repeated sanitizer/Valgrind scans are expensive and
should not become an accidental default path.

If a target terminates with `SIGSEGV`, `SIGABRT`, `SIGBUS`, or `SIGFPE` and no
more precise detector has emitted a finding, `observe` records an
`unclassified_crash` finding with `evidence.crash`. This is intentionally
signal evidence, not a guessed memory-bug class. Target stdout/stderr are
captured under the target `logs/` directory and referenced from the crash
evidence for agent inspection.

Primary outputs:

- `build/observe-demo/run-summary.json` - run-level observation summary
- `build/observe-demo/targets/copy_overrun_case/findings.json` - target findings
- `build/observe-demo/targets/copy_overrun_case/evidence-pack.json` - target evidence pack
- `build/observe-demo/targets/copy_overrun_case/dependencies.json` - target binary/dependency metadata
- `build/observe-demo/targets/copy_overrun_case/issue-groups.json` - stable issue groups
- `build/observe-demo/targets/copy_overrun_case/analysis.json` - target run metadata
- `build/observe-demo/targets/copy_overrun_case/logs/` - captured target stdout/stderr
- `build/observe-demo/run-summary.json` target diagnostics - sandbox/native capability status and remediation

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

This re-executes the recorded binary with args and cwd from `analysis.json`,
preferring the captured binary under `bins/` when present, and writes
`replay/results.json`.

### Validate a crashpack

```bash
cargo run -p rerun -- crashpack validate build/invalid-free
```

### Run the Phase 1 RC gate

```bash
make rc
```

This runs active Rust checks/tests, the golden baseline, and user-style external samples.

### Run the current closeout gate

```bash
make phase4
```

`make phase4` runs the Phase 2 gate, observation-run smoke tests,
project-shaped fixtures, observation hit-rate scoring, and lower-level hit-rate
scoring. Optional `recc`/LLVM validation is intentionally excluded from the
phase gate and remains available through `make recc-smoke`.

The individual gates remain available:

```bash
make phase2
make observe-smoke
make project-smoke
make observe-hit-rate
make support-matrix-smoke
make phase5-closeout-smoke
make hit-rate
make recc-smoke
```

`make phase2` runs the RC gate, Valgrind escalation smoke, ASan binary smoke,
agent summary smoke, and replay smoke. `make observe-smoke` validates the Phase
4 observation-run path against clean, native finding, signal-only crash,
deep-escalation, and fingerprint stability cases. `make project-smoke`
validates project-shaped observation fixtures including multi-file, args/cwd,
multi-binary, shared-library, Valgrind-first, and timeout cases. `make
observe-hit-rate` writes
`build/observe-hit-rate/summary.json` with observation-run target statuses,
native findings, issue groups, escalation outcomes, next commands, and generated
agent summaries for the project corpus. `make hit-rate` records native and
escalation outcomes for the current user-style corpus. `make recc-smoke`
validates optional compiler-wrapper wiring outside the primary runtime path.

Phase 5 adds:

```bash
make support-matrix-smoke
make phase5
```

`make support-matrix-smoke` validates `docs/support-matrix.json` against the
hit-rate, observe-hit-rate, ASan, LSan, UBSan, and signal-crash validation
scripts. `make phase5-closeout-smoke` scans active production paths for
sample-specific or hotfix-like logic. `make phase5` runs both checks plus the
Phase 4 gate; optional `recc`/LLVM validation is deliberately separate.

Phase 5 closeout details and manual dry runs are documented in
`docs/phase5-closeout.md`.

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

### Validate LSan escalation

```bash
make lsan-smoke
```

LSan validation uses binaries built under `build/user-samples-lsan/`. This is
deliberate: standalone LSan only applies when the target was compiled with
`-fsanitize=leak`. Leak support for normal binaries remains Valgrind-backed.

### Validate UBSan escalation

```bash
make ubsan-smoke
```

UBSan validation uses binaries built under `build/user-samples-ubsan/`. This is
deliberate: UBSan only applies when the target was compiled with
`-fsanitize=undefined`.

### Validate optional recc wiring

```bash
make recc-smoke
```

This checks the optional compiler-wrapper path and LLVM pass build. It does not
replace `rerun observe` or `rerun run --native`, and it is intentionally not
part of `make phase2`, `make phase4`, or `make phase5`.

### Score hit rate

```bash
make hit-rate
jq . build/hit-rate/summary.json
```

The current corpus includes native-confirmed heap write overflows through
`memcpy`, `memmove`, `memset`, scoped `strcpy`, and scoped `strncpy`; native
allocator tracking for `malloc`, `calloc`, `realloc`, `posix_memalign`,
`aligned_alloc`, bounded `strdup` inputs, and default libstdc++ C++ new/delete
families; native double/invalid-free and allocator-mismatch cases; native fd
lifecycle coverage for `fd_leak`, `double_close`, and `invalid_close`,
including `dup`, `dup2`, and `fcntl(F_DUPFD*)` descriptor ownership; clean
negatives; native signal-only `unclassified_crash` observation smoke for
supported fatal signals; and Valgrind-first `use_after_free` and `memory_leak` cases.
Valgrind confirms native `fd_leak`; `double_close` and `invalid_close`
escalation are marked unsupported until there is a reliable tool-backed
confirmation path. `strcat`, `strncat`, custom C++ allocator overloads,
placement new/delete, nothrow operators, aligned C++17 allocation overloads,
socket lifecycle, pipe lifecycle, `accept`, fork/exec inheritance, and
cross-process fd handoff remain deferred.
`strdup` allocation size tracking is native-supported for bounded strings, but
source provenance can remain unresolved when the captured allocation stack stays
inside libc. `invalid_close` can also have unresolved source provenance when the
target exits before the action stack can be fully symbolized; the binary-offset
stack is still preserved in the finding.

`build/hit-rate/summary.json` and `build/observe-hit-rate/summary.json` include
`support_matrix` and `coverage_by_class` fields. Those reports are intended to
make production risk visible: they show which classes are native-supported,
tool-backed, unsupported, or not covered by the current product claim. They are
not exhaustive guarantees across every allocator, libc/libstdc++ variant, build
system, dynamic loader pattern, descriptor ownership pattern, or nondeterministic
thread schedule.

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

To run LSan on a no-finding crashpack, use an LSan-instrumented target:

```bash
./scripts/build-user-samples.sh
./target/release/rerun run --native build/user-samples-lsan/direct_leak --output build/lsan-demo
./target/release/rerun escalate build/lsan-demo --tool lsan --scan-binary
jq . build/lsan-demo/escalations/results.json
```

Running `--tool lsan` on a normal binary is rejected with an explicit
`-fsanitize=leak` build requirement.

To run UBSan on a no-finding crashpack, use a UBSan-instrumented target:

```bash
./scripts/build-user-samples.sh
./target/release/rerun run --native build/user-samples-ubsan/signed_overflow --output build/ubsan-demo
./target/release/rerun escalate build/ubsan-demo --tool ubsan --scan-binary
jq . build/ubsan-demo/escalations/results.json
```

Running `--tool ubsan` on a normal binary is rejected with an explicit
`-fsanitize=undefined` build requirement.

## Active Components

- `rerun/` - native CLI/orchestration
- `runtime/agent/re-mini.c` - C agent
- `runtime/bpf/` - BPF programs
- `re-crashpack/` - shared artifact types and writer helpers used by `rerun`
- `re-escalate/` - escalation adapters
- `re-rules/` - deferred rule-engine primitives plus symbolization support; not the active finding engine
- `recc/` - optional compiler wrapper; not required for the native MVP path
- `llvm-passes/` - optional compiler pass experiments; not required for native runtime analysis

## Docs

- [`QUICKSTART.md`](QUICKSTART.md)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`docs/deferred-components.md`](docs/deferred-components.md)
