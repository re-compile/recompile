# Quickstart

This quickstart covers the only supported workflow right now: Linux-native analysis, preferably inside Docker.

## Option 1: Docker-native

From the repo root:

```bash
docker build -t recompile-bootstrap:host .
docker run --rm -it --privileged --pid=host \
  -v "$PWD":/workspace/recompile \
  recompile-bootstrap:host bash
```

Inside the container:

```bash
cd /workspace/recompile/recompile
make phase6
```

Use `make rc` when you only need the quicker Phase 1 regression gate.

## Option 2: Native Linux host

```bash
cd recompile
cargo build --release -p rerun
./scripts/build-examples.sh
./target/release/rerun observe build/examples/double_free --output build/double-free-demo
jq . build/double-free-demo/run-summary.json
```

## Golden Regression Set

The current baseline goldens are:

- `build/examples/memcpy_overflow`
- `build/examples/double_free`
- `build/examples/invalid_free`

Expected findings:

- `memcpy_overflow` -> `heap_overflow`
- `double_free` -> `double_free`
- `invalid_free` -> `invalid_free`

Run the current aggregate validation gate with:

```bash
make phase6
```

Run the quicker Phase 1 RC gate with:

```bash
make rc
```

Run only the golden baseline with:

```bash
./scripts/validate-phase1.sh
```

Or from `recompile/`:

```bash
make phase1
```

## Bring Your Own Binary

Build your binary with debug info and avoid compiler rewrites that can remove the libc calls the native agent traces:

```bash
clang -g -O0 -fno-omit-frame-pointer \
  -fno-builtin -fno-builtin-memcpy -fno-builtin-memmove \
  -fno-builtin-memset -fno-builtin-strcpy -fno-builtin-strncpy \
  -fno-builtin-free -fno-builtin-malloc -fno-builtin-calloc \
  -fno-builtin-realloc -fno-builtin-posix_memalign \
  -fno-builtin-aligned_alloc -fno-builtin-strdup \
  -o my_test my_test.c
```

Run it under `rerun`:

```bash
./target/release/rerun observe ./my_test --output build/my-test
jq . build/my-test/run-summary.json
```

Findings include `provenance.source_status`, which is `resolved` when source is
known and `unresolved` when the tool refuses to guess.

Confirm a finding with Valgrind:

```bash
./target/release/rerun escalate build/my-test/targets/my_test --tool valgrind
jq . build/my-test/targets/my_test/escalations/results.json
```

For a no-finding crashpack, run an explicit Valgrind binary scan:

```bash
./target/release/rerun escalate build/my-test/targets/my_test --tool valgrind --scan-binary
jq . build/my-test/targets/my_test/escalations/results.json
```

Confirm an already-ASan-built binary with ASan:

```bash
clang -g -O0 -fno-omit-frame-pointer -fsanitize=address \
  -o my_asan_test my_test.c

./target/release/rerun run --native ./my_asan_test --output build/my-asan-test
./target/release/rerun escalate build/my-asan-test --tool asan --scan-binary
jq . build/my-asan-test/escalations/results.json
```

ASan is not a standalone binary checker. If the target was not compiled with
`-fsanitize=address`, `rerun escalate --tool asan` rejects it instead of
guessing or rebuilding from source.

Assert an expected class for one binary:

```bash
./scripts/validate-binary.sh --binary ./my_test --expect-class heap_overflow
```

Assert that one binary is clean:

```bash
./scripts/validate-binary.sh --binary ./my_test --expect-none
```

Run the checked user-style samples:

```bash
make external-smoke
```

Run the checked Valgrind escalation smoke:

```bash
make escalation-smoke
```

This validates positive confirmations for the current user-style bug samples
and clean-negative confirmations for the current clean samples.
The Valgrind-first bug classes currently include `use_after_free` and
`memory_leak`. Native `fd_leak` is also Valgrind-confirmable.

Run the checked ASan escalation smoke:

```bash
make asan-smoke
```

Run the checked LSan escalation smoke:

```bash
make lsan-smoke
```

Run the checked UBSan escalation smoke:

```bash
make ubsan-smoke
```

Run the optional compiler-wrapper smoke:

```bash
make recc-smoke
```

This verifies that `recc` can compile a small C binary, write its manifest, and
build the optional LLVM pass. It is separate from the primary `rerun observe`
and `rerun run --native` workflows.

Run the current hit-rate evaluation:

```bash
make hit-rate
jq . build/hit-rate/summary.json
```

Run the current aggregate validation:

```bash
make phase6
```

Use `make hit-rate` when you only need the native/escalation corpus score.

`make recc-smoke` remains available as an explicit optional wiring check. It is
not part of the current phase gates.

To inspect the no-finding path:

```bash
./scripts/build-user-samples.sh
./target/release/rerun run --native build/user-samples/clean_bounded_memcpy --output build/clean-demo
```

## Output Contract

Canonical persisted output:

- `findings.json`

Debug/streaming output only:

- `re-findings.jsonl`
- `RE:FINDING:` lines in logs

## Known Constraints

- Docker-native tracing requires `--privileged --pid=host`
- `rerun observe` writes `targets[].diagnostics` so agents can see whether
  Linux, eBPF, BTF, ptrace, PID namespace, privilege, native artifacts, and
  escalation tools are available.
- If native tracing is unavailable and `--native-only` is not set, `observe`
  attempts a tool-only fallback by creating a minimal crashpack and running a
  whole-binary Valgrind scan. `--deep` also attempts ASan, LSan, and UBSan scans
  when the target binary/tooling supports them.
- Valgrind confirmation requires `valgrind` in the Docker image or host PATH
- `invalid_free` may not resolve to a user source file on the current arm64 Docker build even though the finding class is correct
- VM mode is deferred
- macOS-first development is deferred
