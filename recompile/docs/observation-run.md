# Observation Run Contract

Phase 4 introduces the observation run as the top-level local observability artifact.

The human entry point is:

```bash
rerun observe ./build/app -- --input fixtures/input.txt
```

The existing `rerun run --native <binary>` command remains the low-level crashpack primitive. `rerun observe` wraps that primitive and adds run-level summaries. Observe-level automatic escalation is tracked as a later Phase 4 slice.

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
- `findings`: the target ran and produced one or more findings
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

The current MVP supports one binary, args after `--`, `--cwd`, `--output`, `--timeout-ms`, and `--native-only`. Automatic escalation, dependency metadata, issue groups, and project-style fixtures are tracked as later Phase 4 slices.
