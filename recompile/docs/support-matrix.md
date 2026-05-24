# Phase 5 Support Matrix

The source of truth for class support is `docs/support-matrix.json`. This page is the human-readable summary.

## Status Terms

- `supported`: implemented and covered by committed positive cases plus practical clean negatives.
- `instrumented_binary_supported`: supported only when the user supplies a binary already built with the relevant sanitizer.
- `observed_only`: the runtime observes concrete failure evidence, but does not claim a precise root-cause class.
- `unsupported`: not supported by that detector/tool path.
- `not_applicable`: the tool is not intended to confirm that class.
- `planned`: intentionally deferred.
- `not_covered`: not part of the current product claim.

## Current Native Coverage

- `heap_overflow`: native-supported for allocator plus bounded libc copy/string operations currently in the corpus.
- `double_free`: native-supported through allocator lifecycle tracking.
- `invalid_free`: native-supported through allocator lifecycle tracking.
- `allocator_mismatch`: native-supported for default libstdc++ new/delete-family mismatches currently in the corpus.
- `fd_leak`: native-supported for current libc open/close-family tracking.
- `double_close`: native-supported, but tool confirmation is not wired.
- `invalid_close`: native-supported, but tool confirmation is not wired.
- `unclassified_crash`: observed for supported fatal signals when no precise detector fires.

## Current Tool-Backed Coverage

- Valgrind confirms: `heap_overflow`, `double_free`, `invalid_free`, `allocator_mismatch`, `fd_leak`, `use_after_free`, `memory_leak`.
- ASan confirms already-instrumented `use_after_free` today and may confirm overlapping memory classes when users provide ASan binaries.
- LSan confirms already-instrumented `memory_leak` binaries.
- UBSan confirms already-instrumented UB classes: `signed_integer_overflow`, `shift_out_of_bounds`, `null_pointer_use`, `misaligned_pointer`, and `bounds`.

## Explicit Non-Claims

- Native eBPF does not currently detect arbitrary dereference-based `use_after_free`.
- Native eBPF does not currently claim general `memory_leak` detection.
- Native eBPF does not currently classify stack/global overflows, uninitialized reads, data races, deadlocks, or nondeterministic failures.
- A fatal signal is not treated as proof of heap overflow, null dereference, stack overflow, or use-after-free unless a detector or tool confirms that class.
- The corpus is regression-oriented, not an exhaustive production proof. Real projects can involve custom allocators, unusual libc/libstdc++ symbols, fork/exec descriptor ownership, plugin-loaded libraries, stripped binaries, missing debug info, and nondeterministic schedules.

## Validation Contract

`make support-matrix-smoke` validates that:

- the JSON matrix is parseable and uses known status values;
- every class referenced by hit-rate, observe-hit-rate, ASan, LSan, or UBSan validation has a matrix row;
- native-supported or observed classes have positive cases in the matrix;
- Phase 5 committed classes stay tied to validation scripts instead of becoming stale prose.

`make phase5` runs the support-matrix smoke plus the Phase 4 gate.

Phase 5 closeout details, manual dry runs, and the active-path stale/hotfix
scan are documented in `docs/phase5-closeout.md`.
