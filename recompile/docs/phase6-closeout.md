# Phase 6 Closeout

Phase 6 added repeated-run and flaky-failure observability on top of the Phase 4 observation-run contract and the Phase 5 coverage matrix. The product claim remains evidence-first: `rerun observe` runs a Linux ELF binary, records native/runtime evidence, optionally escalates selected attempts to tools, and emits deterministic artifacts that agents and humans can inspect without guessing.

## Closeout Gate

Phase 6 is considered closed when the supported Linux-native or Docker-native path passes:

```bash
make phase6
```

`make phase6` expands to:

```bash
make phase5
make repeat-fixtures-smoke
```

`make phase5` keeps the existing support matrix, finding schema, stale/hotfix scan, Phase 4 observation substrate, hit-rate, and escalation smoke tests passing. `make repeat-fixtures-smoke` adds the deterministic repeat-mode corpus.

Optional `recc`/LLVM validation remains deliberately separate:

```bash
make recc-smoke
```

`recc` is not required for the primary `rerun observe <binary>` workflow and is not part of the Phase 6 gate.

## What Phase 6 Added

Phase 6 added the runtime-observability substrate needed to reason about flaky or repeated failures:

- `rerun observe <binary> --repeat N` for bounded repeated observation.
- Per-attempt output directories under `attempts/0001`, `attempts/0002`, and so on.
- Root `run-summary.json` aggregation across attempts.
- `repeat-summary.json` with pass/finding/timeout/failure distributions.
- First-failure and best-evidence attempt selection.
- Cross-attempt issue grouping by stable fingerprint.
- Repeat-aware artifact pointers for crashpacks, findings, evidence packs, and issue groups.
- Repeat-aware next inspection commands.
- Explicit repeat escalation policies: `never`, `first-failure`, `sampled`, and `always`.
- Default repeat policy of `first-failure` unless `--native-only` forces `never`.
- Tool timeout budgets through `--tool-timeout-ms` and per-tool overrides for Valgrind, ASan, LSan, UBSan, and GDB.
- Structured timeout results for escalation tools instead of hidden retries or opaque failures.
- GDB batch enrichment for selected signal/crash evidence under an explicit timeout budget.

## Repeat Fixtures

The committed repeat fixture smoke covers deterministic cases rather than timing-dependent randomness:

- stable clean repeated run
- stable failing repeated run
- state-controlled clean/finding/clean flaky sequence
- repeated timeout run

The flaky fixture uses a counter file in its configured `--cwd`. That keeps the test reproducible while proving the repeat summary can represent mixed outcomes, first failure, best evidence, and issue-group frequency.

## Supported User Shape After Phase 6

The supported early-user path is still binary-first:

```bash
rerun observe ./build/app --output .re -- --args
```

For suspected flaky behavior, the user or coding agent opts into bounded repetition:

```bash
rerun observe ./build/app --repeat 5 --output .re -- --args
```

For expensive tool escalation, the user or agent can keep retries bounded:

```bash
rerun observe ./build/app \
  --repeat 5 \
  --deep \
  --repeat-escalation first-failure \
  --tool-timeout-ms 30000 \
  --output .re \
  -- --args
```

The output is intended to answer:

- Did every attempt pass, or did failures recur?
- Which attempt failed first?
- Which attempt has the best evidence?
- Are repeated findings the same issue or independent issues?
- Which tools ran, skipped, timed out, or were unavailable?
- Which exact artifact should an agent inspect next?

## Phase 6 Non-Claims

Phase 6 does not claim complete nondeterministic debugging. It measures repeated execution behavior and preserves evidence.

The following remain deferred:

- deterministic `rr record`/`rr replay` integration
- custom record/replay engine work
- TSan/MSan support
- general race/deadlock detection
- native arbitrary use-after-free detection without sanitizer or Valgrind evidence
- native general memory leak detection without LSan or Valgrind evidence
- fully portable crashpacks that capture arbitrary inputs, services, filesystem state, network state, or scheduler state

`rr` is intentionally not a Phase 6 blocker. It is Linux-only, kernel/CPU/perf-counter sensitive, and often unreliable inside Docker Desktop or VM-backed environments. It should stay deferred until real Linux-host validation proves it reliable enough to expose as a supported replay backend.

## Closeout Validation Notes

The closeout validation target is `make phase6` in the supported Docker/native Linux environment. It includes the Phase 5 gate and the repeat fixture gate.

Useful focused checks when iterating locally:

```bash
make repeat-fixtures-smoke
make observe-smoke
make external-smoke
```

The Phase 6 contract is not that one clean run proves a codebase safe. The contract is that repeated runs, selected escalations, and timeout/tool status are represented as structured evidence so agents can debug from facts instead of rerunning blindly.
