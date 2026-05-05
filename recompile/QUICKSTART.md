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
make rc
```

## Option 2: Native Linux host

```bash
cd recompile
cargo build --release -p rerun
./scripts/build-examples.sh
./target/release/rerun run --native build/examples/double_free --output build/double-free-demo
jq . build/double-free-demo/findings.json
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

Run the full Phase 1 RC gate with:

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
  -fno-builtin -fno-builtin-memcpy -fno-builtin-free \
  -o my_test my_test.c
```

Run it under `rerun`:

```bash
./target/release/rerun run --native ./my_test --output build/my-test
jq . build/my-test/findings.json
```

Confirm a finding with Valgrind:

```bash
./target/release/rerun escalate build/my-test --tool valgrind
jq . build/my-test/escalations/results.json
```

For a no-finding crashpack, run an explicit Valgrind binary scan:

```bash
./target/release/rerun escalate build/my-test --tool valgrind --scan-binary
jq . build/my-test/escalations/results.json
```

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

Run the current hit-rate evaluation:

```bash
make hit-rate
jq . build/hit-rate/summary.json
```

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
- Valgrind confirmation requires `valgrind` in the Docker image or host PATH
- `invalid_free` may not resolve to a user source file on the current arm64 Docker build even though the finding class is correct
- VM mode is deferred
- macOS-first development is deferred
