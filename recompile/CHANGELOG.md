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

### Fixed
- PID-scoped native runs no longer depend on the old shell-wrapper launch path.
- Docker-native runs now fail loudly when started without a shared host PID namespace.
- Native runs now refresh generated crashpack output before analysis so stale findings do not leak across repeated `--output` directories.
- Shared allocator tracking now uses deterministic BPF map keys, fixing valid bounded `memcpy` runs that could report `invalid_free`.
- PID/binary validation in `re-mini` now uses stronger executable matching and handles `readlink` truncation explicitly.
- The three Linux-native goldens currently verify as distinct findings in the supported Docker path:
  - `invalid_free`
  - `double_free`
  - `heap_overflow`

### Removed
- VM-era bootstrap and ad hoc test scripts that no longer match the supported Linux-native workflow.
