# Changelog

## Unreleased

### Changed
- Linux-native execution is now the primary supported workflow.
- Docker-native tracing is documented and guarded around the required `--privileged --pid=host` setup.
- `rerun --native` now launches the target in a stopped state so probes attach before execution continues.
- `re-mini` now handles arm64 `memcpy` attachment with a runtime-offset fallback when symbol-name attach fails.
- Findings are normalized into canonical `findings.json` arrays while debug output stays in `re-findings.jsonl`.
- Phase 1 now has a canonical regression entry point: `recompile/scripts/validate-phase1.sh` and `make phase1`.
- Phase 1 now has a full RC gate: `make rc`.
- Default bootstrap/toolchain helper paths now build only the active Phase 1 crates.
- Active-path workspace `cargo check` is now clean for the supported Phase 1 crates.
- Added a generic external-binary validator and user-style sample suite for non-golden smoke testing.
- Added a clean `malloc/free` user-style sample for the no-finding path.
- Added a clean bounded-`memcpy` user-style sample for the no-finding path.
- Added structured Valgrind escalation output for existing crashpacks.
- Added `make escalation-smoke` and `make phase2` validation targets.
- The Docker bootstrap image now includes Valgrind for native escalation smoke tests.
- Valgrind escalation smoke now covers all current positive user-style samples and clean-negative samples.
- `rerun escalate --check-clean` now runs explicit Valgrind checks for no-finding crashpacks.
- Added `make hit-rate` to score native and Valgrind escalation outcomes across the current user-style corpus.
- Added Valgrind-first memory leak coverage and the `rerun escalate --scan-binary` alias for no-native-finding binary scans.
- Added Valgrind-first use-after-free coverage.
- Added Valgrind-first file descriptor leak coverage with `fd_leak`.
- Native finding provenance now records explicit `source_status` and can recover source paths from stack summaries or debuginfo-resolved binary-offset frames.
- Added structured ASan escalation for binaries already built with `-fsanitize=address`.
- Added `make asan-smoke` and included it in `make phase2`.
- Added `make recc-smoke` for the optional compiler-wrapper and LLVM pass path.
- `recc` is documented as optional and separate from the primary native runtime flow.
- Marked Phase 2 complete for the current issue-backed escalation/evaluation scope and documented the pre-Phase-3 code review gate.
- Removed stale active workspace surfaces that did not match the supported Linux-native workflow.
- Added key-based finding dedupe so multiple independent findings in one process are preserved.
- Added `evidence-pack.json` as the agent-readable crashpack evidence artifact.
- Added `rerun summarize <crashpack> --format json` for deterministic coding-agent summaries.
- Escalation summaries now link confirmation state back to original finding IDs.
- Added `rerun replay <crashpack> --format json` as the minimal replay contract for recorded binary/args.
- Added `make summarize-smoke` and `make replay-smoke`, both included in `make phase2`.
- Marked Phase 3 complete for the agentic runtime evidence MVP scope.
- Added `rerun observe <binary>` as the Phase 4 local observation-run entry point.
- Added `run-summary.json` for observe-level target status, artifact links, finding totals, escalation summaries, issue group counts, and next inspection commands.
- Added observe-level `--cwd`, `--timeout-ms`, `--native-only`, and `--deep` modes.
- Added observe-level escalation policy: native first, Valgrind confirmation for native findings, Valgrind scans in deep mode, and ASan scans only for already-instrumented binaries.
- Added `dependencies.json` to capture ELF identity, debug-info state, interpreter, dynamic dependencies, RPATH/RUNPATH, and readelf/ldd availability.
- Local non-system dynamic dependencies detected from `ldd` are copied into crashpack `bins/lib` for replay/escalation support.
- Added deterministic finding fingerprints and `issue-groups.json`.
- Added project-shaped fixtures covering multi-file, args/cwd, multi-binary, shared-library, Valgrind-first, and timeout observation paths.
- Added `make observe-smoke`, `make project-smoke`, `make observe-hit-rate`, and the aggregate `make phase4` closeout gate.
- Marked Phase 4 complete for the local runtime observability foundation.

### Fixed
- PID-scoped native runs no longer depend on the old shell-wrapper launch path.
- Docker-native runs now fail loudly when started without a shared host PID namespace.
- Native runs now refresh generated crashpack output before analysis so stale findings do not leak across repeated `--output` directories.
- ASan escalation now rejects non-instrumented binaries clearly instead of attempting an implicit source rebuild.
- Shared allocator tracking now uses deterministic BPF map keys, fixing valid bounded `memcpy` runs that could report `invalid_free`.
- PID/binary validation in `re-mini` now uses stronger executable matching and handles `readlink` truncation explicitly.
- Crashpack repro scripts now target the captured binary name instead of a hardcoded `./bins/target`.
- `rerun replay` now applies the recorded cwd and canonicalizes the captured binary before execution.
- Observe-level Valgrind escalation now respects recorded cwd and canonicalized captured binaries.
- The three Linux-native goldens currently verify as distinct findings in the supported Docker path:
  - `invalid_free`
  - `double_free`
  - `heap_overflow`

### Removed
- VM-era bootstrap and ad hoc test scripts that no longer match the supported Linux-native workflow.
- Removed the legacy unreferenced escalation tool module that duplicated stale sanitizer implementations.
