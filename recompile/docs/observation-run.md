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

## Current Slice

The current MVP supports one binary, args after `--`, `--cwd`, `--output`, `--timeout-ms`, `--native-only`, and `--deep`.

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
- target `next_commands`
- a generated `agent-summary.json` for each target crashpack

This is separate from `make hit-rate`, which remains the lower-level
native/escalation corpus report for single-binary user samples.
