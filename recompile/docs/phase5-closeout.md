# Phase 5 Closeout

Phase 5 expanded memory/resource coverage while preserving the Phase 4 observation-run contract. The product claim remains evidence-first: `rerun observe` runs the target, records native/runtime evidence, optionally escalates to tools, and emits deterministic artifacts for agents and humans.

## Exit Criteria

Phase 5 is considered closed when all of the following pass on the supported Linux-native or Docker-native path:

```bash
cargo test --workspace --all-targets
make phase5
```

`make phase5` expands to:

```bash
make support-matrix-smoke
make phase5-closeout-smoke
make phase4
```

The Docker invocation used for closeout is:

```bash
docker run --rm --privileged --pid=host \
  -v "$PWD":/workspace/recompile \
  -e RECOMPILE_SKIP_BOOTSTRAP=1 \
  recompile-bootstrap:host \
  bash -lc 'cd /workspace/recompile/recompile && make phase5'
```

## What Phase 5 Added

- Tool-backed finding promotion for escalation outputs.
- UBSan adapter for already-UBSan-built binaries.
- Standalone LSan adapter for already-LSan-built binaries.
- Native default-libstdc++ allocator-family tracking for current new/delete mismatch cases.
- Native fd lifecycle tracking for `open`/`openat`/`open64`/`openat64`/`creat` and `close`.
- Native signal-only `unclassified_crash` evidence for `SIGSEGV`, `SIGABRT`, `SIGBUS`, and `SIGFPE` when no precise detector fires.
- Machine-readable support matrix at `docs/support-matrix.json`.
- `coverage_by_class` fields in hit-rate reports.
- `make phase5` as the aggregate Phase 5 validation gate.

## Manual Dry Runs

These commands are intended for a Linux host or the supported Docker container. They are narrower than `make phase5`, but easier to inspect when validating the product manually.

### Native Copy/Write Evidence

```bash
./scripts/build-user-samples.sh
cargo build -q -p rerun --release
rm -rf build/manual-phase5-copy
./target/release/rerun observe \
  build/user-samples/copy_overrun_case \
  --output build/manual-phase5-copy
./target/release/rerun summarize \
  build/manual-phase5-copy/targets/copy_overrun_case \
  --format json > build/manual-phase5-copy/agent-summary.json
jq '.targets[0].status, .targets[0].findings_by_class' build/manual-phase5-copy/run-summary.json
jq '.findings[0].class, .findings[0].operation' build/manual-phase5-copy/agent-summary.json
```

Expected result: `findings`, one `heap_overflow`, operation `memcpy`, Valgrind confirmation in the target escalation results.

### Allocator Lifecycle Evidence

```bash
rm -rf build/manual-phase5-allocator
./target/release/rerun observe \
  build/user-samples/cxx_new_free_mismatch \
  --output build/manual-phase5-allocator
jq '.targets[0].findings_by_class' build/manual-phase5-allocator/run-summary.json
jq '.[0].evidence.memory.alloc_family, .[0].evidence.memory.dealloc_family' \
  build/manual-phase5-allocator/targets/cxx_new_free_mismatch/findings.json
```

Expected result: one `allocator_mismatch`, with `alloc_family` and `dealloc_family` populated.

### Tool-Backed Valgrind-First Evidence

```bash
rm -rf build/manual-phase5-valgrind
./target/release/rerun observe --deep \
  build/user-samples/use_after_free_case \
  --output build/manual-phase5-valgrind
jq '.targets[0].findings_by_class, .targets[0].escalation' \
  build/manual-phase5-valgrind/run-summary.json
```

Expected result: native remains clean/unsupported for arbitrary dereference UAF, Valgrind promotes one `use_after_free` finding, and sanitizer adapters report `not_applicable` unless the binary is instrumented.

### Sanitizer-Backed Evidence

```bash
rm -rf build/manual-phase5-ubsan
./target/release/rerun observe --deep \
  build/user-samples-ubsan/signed_overflow \
  --output build/manual-phase5-ubsan
jq '.targets[0].findings_by_class, .targets[0].escalation' \
  build/manual-phase5-ubsan/run-summary.json
```

Expected result: UBSan promotes one `signed_integer_overflow`; ASan/LSan report `not_applicable` for that binary.

### Resource Lifecycle Evidence

```bash
rm -rf build/manual-phase5-fd
./target/release/rerun observe \
  build/user-samples/fd_leak_case \
  --output build/manual-phase5-fd
jq '.targets[0].findings_by_class, .targets[0].escalation' \
  build/manual-phase5-fd/run-summary.json
```

Expected result: one native `fd_leak`, with Valgrind confirmation. `double_close` and `invalid_close` are native-supported but tool confirmation is intentionally marked unsupported.

### Crash/Signal Evidence

```bash
rm -rf build/manual-phase5-crash
./target/release/rerun observe --native-only \
  build/user-samples/crash_segv_case \
  --output build/manual-phase5-crash
jq '.targets[0].exit, .targets[0].findings_by_class' \
  build/manual-phase5-crash/run-summary.json
jq '.[0].evidence.crash' \
  build/manual-phase5-crash/targets/crash_segv_case/findings.json
```

Expected result: one `unclassified_crash`, `signal_name` `SIGSEGV`, and target stdout/stderr log paths. This is signal evidence only; it is not a guessed memory class.

## Closeout Scan

`make phase5-closeout-smoke` runs `scripts/validate-phase5-closeout.sh`. The scan checks active production paths for sample/golden-specific strings and hotfix markers. It intentionally excludes fixtures, samples, docs, tests, generated build output, and the deferred `re-rules` rule-engine demo.

The current scan result is expected to report zero violations.

## Production Validation Boundary

The test suite is regression-grade, not exhaustive production proof. It covers representative positive and clean-negative paths for the committed product claim, but real projects can still expose unsupported cases:

- custom allocators and overloaded C++ allocation operators;
- placement/nothrow/aligned C++17 allocation overloads;
- fd duplication, inheritance, and ownership transfer;
- socket/pipe/accept lifecycle tracking;
- stripped binaries or missing debug info;
- plugin-loaded libraries and unusual dynamic loader behavior;
- nondeterministic races, deadlocks, and flaky timing-sensitive failures;
- stack/global overflows and uninitialized reads without sanitizer/tool support.

Those are intentionally reflected as `unsupported`, `planned`, or `not_covered` in `docs/support-matrix.json` until deterministic evidence exists.
