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
- normalized call site
- normalized allocation site
- normalized free site when available
- access size
- allocation size

The fingerprint deliberately excludes pointer addresses, PIDs, timestamps,
absolute crashpack output directories, and escalation artifact names because
those vary between runs. Repeated executions of the same bug path should keep
the same fingerprint. Independent findings should split when their class,
operation, source site, lifecycle site, or size evidence differs.

## Phase 4 Complete Scope

The current Phase 4 baseline supports one binary, args after `--`, `--cwd`,
`--output`, `--timeout-ms`, `--native-only`, and `--deep`.

Default escalation policy:

- native first
- Valgrind confirmation when native findings exist
- no heavy scan when native is clean

Deep escalation policy:

- native first
- Valgrind binary scan even when native is clean
- ASan binary scan when the binary is already ASan-instrumented
- ASan `not_applicable` status for normal non-ASan binaries

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
make phase4
```

The equivalent expanded gate is:

```bash
make phase2
make observe-smoke
make project-smoke
make observe-hit-rate
make hit-rate
make recc-smoke
```

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
