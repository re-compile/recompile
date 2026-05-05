# re:compile

`re:compile` is a Linux-native runtime analysis toolchain for C/C++ memory bugs.

Current supported path:

- build or provide a Linux ELF binary
- run `rerun run --native <binary>`
- attach the C eBPF agent in `recompile/runtime/agent/re-mini.c`
- persist canonical findings to `findings.json`
- keep streaming/debug output in `re-findings.jsonl`

## Status

Phase 0 is complete on the supported path.
Phase 1 is complete for the Linux-native MVP scope.

Validated native findings in Docker:

- `memcpy_overflow` -> `heap_overflow`
- `double_free` -> `double_free`
- `invalid_free` -> `invalid_free`

Current priority is Phase 2: confirm findings with real escalation tools and broaden user-binary coverage.

## Supported Environment

Primary supported environment:

- Linux host, or
- Docker with `--privileged --pid=host`

That PID namespace requirement is mandatory for the current eBPF tracing flow.

## Quick Start

```bash
git clone <repo-url>
cd ai-compiler
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

To smoke-test the bring-your-own-binary path:

```bash
make external-smoke
```

To smoke-test Valgrind confirmation:

```bash
make escalation-smoke
```

That smoke validates Valgrind confirmations for the current positive user-style
samples and verifies Valgrind stays unconfirmed on clean user-style samples.

To score the current native/escalation hit rate:

```bash
make hit-rate
jq . build/hit-rate/summary.json
```

## Repo Layout

- `recompile/` - active Rust/C workspace
- `Dockerfile` - supported bootstrap image

## Core Docs

- [`recompile/README.md`](recompile/README.md)
- [`recompile/QUICKSTART.md`](recompile/QUICKSTART.md)
- [`recompile/ARCHITECTURE.md`](recompile/ARCHITECTURE.md)

## Not In Scope Right Now

- VM-first workflow
- macOS-first support
- Rust runtime agent
- `recc` as a required MVP path
- CI as a release gate

## Phase 1 RC Gate

The current release-candidate regression command is:

```bash
cd recompile
make rc
```

This runs active Rust checks/tests, the three golden regressions, and the user-style external sample suite.

## Phase 2 Evaluation

The current Phase 2 hit-rate command is:

```bash
cd recompile
make hit-rate
```

It writes per-case native and Valgrind escalation outcomes to `build/hit-rate/summary.json`.
Some Phase 2 classes, such as `use_after_free` and `memory_leak`, are currently Valgrind-first and marked as native-unsupported in that summary.

Golden-only baseline:

```bash
cd recompile
make phase1
```

## Bring Your Own Binary

For early technical users, the supported workflow is runtime triage for a Linux ELF binary the user already knows how to build:

```bash
clang -g -O0 -fno-omit-frame-pointer \
  -fno-builtin -fno-builtin-memcpy -fno-builtin-free \
  -o my_test my_test.c

./target/release/rerun run --native ./my_test --output build/my-test
jq . build/my-test/findings.json
```

To assert an expected class for one binary:

```bash
./scripts/validate-binary.sh --binary ./my_test --expect-class heap_overflow
```

To run Valgrind confirmation on an existing crashpack:

```bash
./target/release/rerun escalate build/my-test --tool valgrind
jq . build/my-test/escalations/results.json
```

For a crashpack with no native findings, run an explicit Valgrind binary scan:

```bash
./target/release/rerun escalate build/my-test --tool valgrind --scan-binary
```
