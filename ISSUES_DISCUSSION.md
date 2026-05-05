# re:compile Issues Discussion

*Updated after the Phase 1 bring-your-own-binary and finding-quality slices.*

---

## Summary

The old blockers are no longer the main story.

The active Linux-native path is now working on the supported Docker flow:

- `memcpy_overflow` -> `heap_overflow`
- `double_free` -> `double_free`
- `invalid_free` -> `invalid_free`

The remaining work is narrower than the original architecture repair, but Phase 1 is **not** ready until one user-code correctness blocker is handled.

What still matters now:

1. keep the Docker-native workflow explicit and repeatable
2. add regression coverage for the three goldens
3. fix the valid `malloc -> bounded memcpy -> free` false positive
4. keep symbolization good enough for user-visible primary locations
5. decide whether any remaining arm64 source-location gaps are acceptable for the MVP

---

## Part 1: Current Issues And Constraints

### Issue #1: Docker Native Requires Shared PID Namespace

**Location**: `recompile/rerun/src/native.rs`, `recompile/runtime/agent/re-mini.c`
**Status**: Known constraint
**Severity**: High operationally

The supported native Docker flow requires `--privileged --pid=host`.

Without a shared PID namespace:

- the launched target PID seen by `rerun` and the kernel-visible PID seen by BPF events diverge
- PID-scoped filtering drops the real events
- the analysis can appear to succeed while producing no findings

This is no longer a hidden correctness bug. It is now a documented support constraint and the code errors early in the unsupported case.

### Issue #2: Valid Bounded `memcpy` Can Corrupt Finding Quality

**Location**: `recompile/runtime/agent/re-mini.c`, allocator/copy probe interaction
**Status**: Open
**Severity**: High

A valid user-code pattern still reports `invalid_free` in the supported Docker-native flow:

```c
char *dst = malloc(64);
memcpy(dst, "safe copy", 10);
free(dst);
```

This is not a stale-output issue anymore. `rerun run --output <dir>` now refreshes generated crashpack artifacts before each run, and the repro still produces `invalid_free` with a fresh output directory.

The next fix must be generic:

- no bypass based on source file name, binary name, or sample identity
- add a committed regression sample for this clean pattern
- inspect allocator state and copy-probe map sharing before changing classification behavior

### Issue #3: `invalid_free` Source Location May Still Be Missing

**Location**: `recompile/runtime/agent/re-mini.c`, native Docker arm64 builds
**Status**: Known limitation
**Severity**: Medium

After the symbolization and launch fixes, user-code source paths are good for the current user-style finding samples. Some `invalid_free` paths may still degrade to raw binary offsets on the current arm64 Docker build.

This should not block the finding class, severity, or provenance, but it remains a finding-quality issue after the false-positive gate is closed.

### Issue #4: Phase 1 Readiness Is Mostly A Scope Decision Now

**Location**: roadmap / release criteria
**Status**: Open
**Severity**: Medium

The major plumbing blockers for the current MVP scope are no longer open, but the safe-memcpy false positive is a correctness gate.

What remains is mostly a release-boundary decision:

- the baseline regression path exists and passes
- the user-style external smoke path exists and passes
- the clean `malloc/free` no-finding sample exists and passes
- stale output directories no longer leak findings across runs
- the active-path crate warnings have been trimmed
- docs/scripts now point at the same supported flow
- the main remaining correctness limitation is the valid bounded-`memcpy` false positive

For the current MVP definition, Phase 1 should not be called ready until that false positive is resolved or explicitly scoped out.

### Issue #5: Regression Coverage Needs To Stay Canonical

**Location**: repo workflow / Docker validation path
**Status**: Reduced
**Severity**: Medium

The repo now has a supported regression script:

- `recompile/scripts/validate-phase1.sh`
- `cd recompile && make phase1`
- `recompile/scripts/validate-binary.sh` for one external binary
- `cd recompile && make external-smoke` for user-style non-golden samples
- `recompile/samples/user-binaries/clean_malloc_free.c` for the no-finding path

That fixes the worst ad hoc problem, but the discipline still matters:

- docs should keep pointing at that one command
- future cleanup should not reintroduce parallel “happy path” scripts that drift from it

---

## Part 2: Issues That Are Now Resolved

### Resolved: Findings Contract Mismatch Across Components

The code now treats:

- `findings.json` as the canonical persisted format
- `RE:FINDING:` and `re-findings.jsonl` as streaming/debug only

This is now aligned across the active native/crashpack/escalation flow.

### Resolved: VM And Native Mixed Assumptions In The Supported Path

VM mode is no longer treated as part of the supported workflow.

The stale VM launcher path and related stub/deferred code were removed from the active workspace path, and `rerun` is native-first.

### Resolved: Broken Subprocess Wiring For Escalation And Harnesses

The active path no longer depends on the old VM-era subprocess orchestration.

The supported flow now uses direct library wiring in the active native path.

### Resolved: Escalation Guessing Source/Binary Paths From Example Names

Escalation now consumes explicit finding provenance instead of inferring file paths from `finding.class` or binary basenames.

### Resolved: Crashpack Generation Assuming One Example Binary

Crashpack generation now accepts real inputs and no longer assumes one fixed example.

### Resolved: Symbolizer Test Failures In `re-rules`

The earlier symbolizer recursion/test failures were repaired and the targeted tests pass.

### Resolved: Demo/Stale Workspace Components In The Active Path

The following stale or deferred components were removed from the active workspace path:

- `vm-launcher`
- Rust agent stubs
- VM runtime remnants
- LSP/MCP stubs
- stale helper/generated assets tied to removed workflows

### Resolved: Stale Output Directories Could Re-report Old Findings

`rerun run --output <dir>` now removes known generated crashpack artifacts before a new analysis. This prevents old `findings.json`, `.re`, `bins`, logs, and manifests from being treated as current-run output.

---

## Part 3: Recommended Next Order

1. Fix the valid bounded-`memcpy` false positive without a hotfix
2. Add the false-positive repro as a committed clean regression sample
3. Keep the supported Docker-native invocation explicit everywhere
4. Keep `recompile/scripts/validate-phase1.sh`, `make phase1`, and `make external-smoke` as the canonical regression path
5. Decide whether any remaining source-path resolution gaps are release gates or post-RC polish
6. If correctness is clean, call Phase 1 ready for the current MVP scope
7. Then decide what belongs in Phase 2 versus remaining deferred

---

## Part 4: What We Are Explicitly Deferring

- VM-first support
- macOS-first support
- Rust runtime agent
- `recc` as a required MVP path
- CI rollout before the regression path is locked
- broader Phase 2 observability work
