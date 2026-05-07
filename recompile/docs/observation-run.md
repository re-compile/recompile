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

Dependency metadata, issue groups, and project-style fixtures are tracked as later Phase 4 slices.
