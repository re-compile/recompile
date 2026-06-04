# Observation Run Contract

Phase 4 introduces the observation run as the top-level local observability artifact.

The human entry point is:

```bash
rerun observe ./build/app -- --input fixtures/input.txt
```

The existing `rerun run --native <binary>` command remains the low-level crashpack primitive. `rerun observe` wraps that primitive, adds run-level summaries, and records observe-level escalation results.

## Layout

```text
.re/
  run-summary.json
  targets/
    app/
      analysis.json
      findings.json
      evidence-pack.json
      manifest.json
      dependencies.json
      issue-groups.json
      logs/
      bins/
      escalations/
      replay/
```

With `--repeat N`, repeat mode is explicit and attempt-scoped:

```text
.re/
  run-summary.json
  repeat-summary.json
  attempts/
    0001/
      run-summary.json
      targets/
        app/
          findings.json
          evidence-pack.json
          issue-groups.json
    0002/
      run-summary.json
      targets/
        app/
          findings.json
          evidence-pack.json
          issue-groups.json
```

The root `run-summary.json` remains a normal observation summary and aggregates
the per-attempt target summaries with names such as `attempt-0001-app`.
`repeat-summary.json` is the repeat-specific artifact for agents and humans. It
records:

- requested and completed attempt counts
- raw status totals such as `clean`, `findings`, `timeout`, or `failed`
- outcome totals such as `pass`, `finding`, `timeout`, `failure`, or `inconclusive`
- finding totals by class across attempts
- one row per attempt with the attempt output root, run summary, crashpack,
  findings, evidence pack, and issue-group paths
- `first_failure`, which points at the first non-pass attempt when one exists
- `best_evidence_attempt`, which prefers the first attempt with findings, then
  timeout/failure evidence if no finding exists
- next inspection commands for the repeat summary, aggregate run summary, and
  each attempt summary

All-pass repeat runs intentionally keep `first_failure` and
`best_evidence_attempt` as `null`.
Repeated deep escalation is policy-gated for now because sanitizer and Valgrind
retries are expensive and must be budgeted deliberately.

`run-summary.json` is versioned by `schemas/observation-run.schema.json` and uses `schema_version: "1.0"` with `purpose: "local_runtime_observation"`.

## Target Statuses

Each observed target has exactly one primary status:

- `clean`: the target ran and no findings were observed on that executed path
- `findings`: the target ran and native or escalation evidence observed one or more findings
- `failed`: the target failed before or during observation for a non-timeout reason
- `timeout`: the target exceeded its configured timeout
- `skipped`: the target was not executed because validation or setup failed
- `tool_unavailable`: an optional tool was requested but unavailable
- `not_applicable`: an optional tool does not apply, such as ASan on a non-ASan binary

Run-level status is derived from target statuses. Partial failure must keep successful target evidence intact.

## Required Target Evidence

Each target summary records:

- binary path
- args
- cwd
- selected environment summary
- structured error reason for failed/skipped/timeout targets
- exit code or signal
- duration and timeout
- finding counts by class
- issue group count
- escalation summaries
- artifact paths
- replay and summarize commands when available
- next inspection commands

## Dependency Metadata

Each target crashpack writes `dependencies.json` and links it from both
`run-summary.json` and `evidence-pack.json`.

The artifact is intentionally non-fatal with respect to optional host tooling:

- `readelf.status` records `available`, `unavailable`, or `failed`
- `ldd.status` records `available`, `unavailable`, or `failed`
- `elf` records class, machine, interpreter, build ID, debug-info presence, RPATH, and RUNPATH when available
- `dynamic_dependencies` records resolved libraries, missing libraries, loader entries, and unknown lines from `ldd`

Missing `readelf` or `ldd` should degrade the metadata instead of failing the
observation run. Failure to write the artifact itself is treated as an output
error because the crashpack would otherwise be incomplete.

## Issue Groups

Each target crashpack writes `issue-groups.json`, annotates each canonical
finding with `fingerprint` and `issue_group_id`, and links the groups from
`evidence-pack.json`, `run-summary.json`, and `rerun summarize`.

Fingerprints are deterministic. The current inputs are:

- finding class
- observed operation or API
- resolved source path when available
- normalized call site when it is deterministic enough for the source
- normalized allocation site
- normalized free site when available
- access size
- allocation size

The fingerprint deliberately excludes pointer addresses, PIDs, timestamps,
absolute crashpack output directories, and escalation artifact names because
those vary between runs. Repeated executions of the same bug path should keep
the same fingerprint. Independent findings should split when their class,
operation, source site, lifecycle site, or size evidence differs.

Native eBPF stack symbolization is opportunistic, so a source call site may be
present in one run and missing in another. For native memory findings that
already have stable source, allocation, and size evidence, the call site stays
visible in the issue-group source context but is not part of the primary
fingerprint. Tool-backed findings from ASan, Valgrind, UBSan, LSan, or GDB can
use normalized tool frames because those outputs are deterministic enough for
the escalation layer.

## Phase 4 And Phase 6 Baseline Scope

The current Phase 4 baseline supports one binary, args after `--`, `--cwd`,
`--output`, `--timeout-ms`, `--native-only`, and `--deep`.

The current Phase 6 baseline adds `--repeat N` for opt-in repeated native
observation runs. Repeat mode runs the same binary multiple times, stores each
attempt independently under `attempts/`, and writes an aggregate
`run-summary.json` plus `repeat-summary.json`. It does not yet write
cross-attempt issue groups or repeated escalation policy artifacts.

Repeat/flaky fixtures are covered by `make repeat-fixtures-smoke`:

- stable clean repeated run
- stable failing repeated run
- state-controlled flaky run with a deterministic clean/finding/clean sequence
- repeated timeout run

The flaky fixture uses a counter file in its `--cwd`; it does not use randomness
or timing races. This keeps repeat-mode tests reproducible while still proving
that `repeat-summary.json` can report mixed pass/fail distributions and select
the first failure and best evidence attempt.

Default escalation policy:

- native first
- Valgrind confirmation when native findings exist
- no heavy scan when native is clean

Deep escalation policy:

- native first
- Valgrind binary scan when native is clean and no sanitizer runtime is present
- explicit Valgrind `skipped` status when sanitizer runtime is present
- ASan binary scan when the binary is already ASan-instrumented
- LSan binary scan when the binary is already LSan-instrumented
- UBSan binary scan when the binary is already UBSan-instrumented
- sanitizer `not_applicable` status for normal non-instrumented binaries

Dependency metadata is captured for each target.
Issue groups are captured for each target.
Replay uses the captured binary and recorded cwd when available.
Project-style fixtures are covered by `make project-smoke`:

- multi-file heap bug
- clean multi-file app
- args/cwd-sensitive app
- multi-binary project
- shared-library target with dependency metadata
- Valgrind-first target
- timeout target

Repeat-specific fixtures are covered by `make repeat-fixtures-smoke`:

- stable clean
- stable failing
- deterministic clean/finding/clean flaky sequence
- timeout

## Observation Hit Rate

`make observe-hit-rate` evaluates the project fixture corpus through the
top-level observation path and writes `build/observe-hit-rate/summary.json`.

The report includes:

- target status totals
- expected vs actual native findings
- issue group counts and fingerprints
- observe-level escalation outcomes
- support-matrix path and per-class coverage summary
- target `next_commands`
- a generated `agent-summary.json` for each target crashpack

This is separate from `make hit-rate`, which remains the lower-level
native/escalation corpus report for single-binary user samples.

The support matrix lives at `docs/support-matrix.json` and is validated with
`make support-matrix-smoke`. It is intentionally explicit about native-supported
classes, sanitizer/tool-backed classes, unsupported classes, and classes that
are not part of the current product claim.

## Sandbox And Fallback Behavior

`rerun observe` is intended to be useful inside coding-agent sandboxes, but
native eBPF tracing is not guaranteed there. The run summary includes
`targets[].diagnostics`, a machine-readable list of checks for Linux support,
privilege, bpffs, BTF, ptrace policy, Docker PID namespace, the `re-mini` agent,
BPF objects, libc discovery, and fallback tools such as Valgrind, GDB, and
Clang.

When native tracing fails for an environment/setup reason and `--native-only`
is not set, observe falls back to tool-only analysis instead of stopping at an
opaque native error. The fallback writes the same target crashpack layout,
records `analysis.json`, captures binary/dependency metadata, writes an empty
native `findings.json` if no native evidence exists, and then runs a
whole-binary Valgrind scan. With `--deep`, it also attempts ASan, LSan, and
UBSan scans. When a sanitizer runtime is present, Valgrind is recorded as
`skipped` and sanitizer scans become the primary evidence path. Missing tools
are reported as `tool_unavailable` or `not_applicable`; they are not treated as
evidence that the target is clean.

`--native-only` is the strict mode for validating the eBPF path. In that mode,
native setup failures remain target failures and no tool-only fallback is run.

## Manual Linux Validation Checklist

Phase 4 should be validated on Linux or in the supported Docker-native setup.
The container must use `--privileged --pid=host` so eBPF events and target PIDs
line up.

From the repository root:

```bash
docker build -t recompile-bootstrap:host .
docker run --rm -it --privileged --pid=host \
  -e RECOMPILE_SKIP_BOOTSTRAP=1 \
  -v "$PWD":/workspace/recompile \
  -w /workspace/recompile/recompile \
  recompile-bootstrap:host bash
```

Inside the container:

```bash
make phase5
```

The equivalent expanded gate is:

```bash
make support-matrix-smoke
make phase5-closeout-smoke
make phase2
make observe-smoke
make project-smoke
make repeat-fixtures-smoke
make observe-hit-rate
make hit-rate
```

`make phase4` remains available as the Phase 4 substrate gate. `make phase5`
adds the support-matrix and closeout scans before running that substrate.
`make phase6` runs `make phase5` and then the deterministic repeat fixture gate.
Optional `recc`/LLVM validation is intentionally separate via `make recc-smoke`.

### Manual Dry Run

This checks the baseline path a technical early user would exercise: build a
small project fixture, observe it with args and cwd, summarize it for an agent,
and replay the captured command.

```bash
./scripts/build-project-fixtures.sh
cargo build -q -p rerun --release
rm -rf build/manual-phase4

./target/release/rerun observe \
  --output build/manual-phase4 \
  --cwd build/project-fixtures/args-cwd/run \
  build/project-fixtures/args-cwd/app \
  -- trigger payload.bin

./target/release/rerun summarize \
  build/manual-phase4/targets/app \
  --format json > build/manual-phase4/agent-summary.json

./target/release/rerun replay \
  build/manual-phase4/targets/app \
  --format json > build/manual-phase4/replay.json

jq . build/manual-phase4/run-summary.json
jq . build/manual-phase4/agent-summary.json
jq . build/manual-phase4/replay.json
```

Expected baseline:

- `run-summary.json` exists with one target.
- the target status is `findings`.
- the target links `analysis.json`, `findings.json`, `evidence-pack.json`,
  `dependencies.json`, `issue-groups.json`, escalation results, and next
  commands.
- `agent-summary.json` includes at least one finding with a stable fingerprint
  and issue group.
- `replay.json` reports `ran: true` and uses the captured binary plus recorded
  cwd.

## Known Limitations

- `rerun observe` currently supports one binary per invocation. Multi-binary
  observation remains represented by project fixtures and future run-level
  orchestration work.
- Build-system takeover is intentionally deferred. Users build their project
  first, then point `rerun observe` at the binary they want to inspect.
- Crashpacks are evidence packs, not fully portable bundles. Local shared
  libraries are copied when detected, but arbitrary inputs/configs/services are
  not automatically captured.
- Replay is minimal binary/args/cwd replay. It is not deterministic
  record/replay and does not restore the full environment, filesystem, network,
  stdin, or scheduler state.
- Native eBPF analysis requires Linux and the supported Docker/native
  permissions. macOS, VM mode, and the Rust agent are deferred.
- ASan escalation applies only to binaries that were already built with ASan.
  `re:compile` does not implicitly rebuild user projects with sanitizers.
- Valgrind/ASan/readelf/ldd availability is reported as structured evidence;
  missing optional tools should not be interpreted as target cleanliness.
- Clean means "no finding on the observed executed path", not "the whole
  codebase is memory safe".
