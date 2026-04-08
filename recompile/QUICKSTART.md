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
./scripts/build-examples.sh
cargo run -p rerun -- run --native build/examples/memcpy_overflow --output build/memcpy-demo
jq . build/memcpy-demo/findings.json
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

## Output Contract

Canonical persisted output:

- `findings.json`

Debug/streaming output only:

- `re-findings.jsonl`
- `RE:FINDING:` lines in logs

## Known Constraints

- Docker-native tracing requires `--privileged --pid=host`
- `invalid_free` may not resolve to a user source file on the current arm64 Docker build even though the finding class is correct
- VM mode is deferred
- macOS-first development is deferred
