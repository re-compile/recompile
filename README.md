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
Phase 2 is complete for the current issue-backed escalation and evaluation scope.
Phase 3 is complete for the agentic runtime evidence MVP scope.
Phase 4 is complete for the local runtime observability foundation.

Validated native findings in Docker:

- `memcpy_overflow` -> `heap_overflow`
- `memmove_overrun_case` -> `heap_overflow`
- `memset_overrun_case` -> `heap_overflow`
- `strcpy_overrun_case` -> `heap_overflow`
- `strncpy_overrun_case` -> `heap_overflow`
- `double_free` -> `double_free`
- `invalid_free` -> `invalid_free`

Valgrind-first coverage currently includes `use_after_free`, `memory_leak`, and
`fd_leak`. Already-instrumented sanitizer adapters cover ASan, LSan, and UBSan
when the user provides binaries built with the matching `-fsanitize=...` flag.

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

To smoke-test ASan confirmation for already-instrumented binaries:

```bash
make asan-smoke
```

ASan support is intentionally narrow: the binary must already be built with
`-fsanitize=address`. `rerun` does not silently rebuild source files or pretend
ASan applies to a normal binary.

To smoke-test the optional compiler-wrapper path:

```bash
make recc-smoke
```

`recc` is an advanced compile-wrapper path. It is not required for the primary
`rerun run --native <binary>` workflow and is not part of the Phase 2 release
gate.

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

The Phase 2 closeout gate is:

```bash
cd recompile
make phase2
make hit-rate
```

`make phase2` runs the RC gate plus Valgrind and ASan escalation smoke tests.
`make hit-rate` writes per-case native and escalation outcomes to
`build/hit-rate/summary.json`.

The optional compiler-wrapper smoke remains separate:

```bash
cd recompile
make recc-smoke
```

`recc` is not part of the primary `rerun run --native <binary>` workflow.

To score only the current native/escalation hit rate:

```bash
cd recompile
make hit-rate
```

Some Phase 2 classes, such as `use_after_free`, `memory_leak`, and `fd_leak`, are currently Valgrind-first and marked as native-unsupported in that summary.

Native findings include `provenance.source_status` so unresolved source
locations are explicit instead of silently missing.

Golden-only baseline:

```bash
cd recompile
make phase1
```

## Bring Your Own Binary

For early technical users, the supported workflow is runtime triage for a Linux ELF binary the user already knows how to build:

```bash
clang -g -O0 -fno-omit-frame-pointer \
  -fno-builtin -fno-builtin-memcpy -fno-builtin-memmove \
  -fno-builtin-memset -fno-builtin-strcpy -fno-builtin-strncpy \
  -fno-builtin-free -fno-builtin-malloc -fno-builtin-calloc \
  -fno-builtin-realloc -fno-builtin-posix_memalign \
  -fno-builtin-aligned_alloc -fno-builtin-strdup \
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

To run ASan confirmation, build the target with ASan first:

```bash
clang -g -O0 -fno-omit-frame-pointer -fsanitize=address \
  -o my_asan_test my_test.c

./target/release/rerun run --native ./my_asan_test --output build/my-asan-test
./target/release/rerun escalate build/my-asan-test --tool asan --scan-binary
jq . build/my-asan-test/escalations/results.json
```

If the binary is not ASan-instrumented, `--tool asan` fails clearly with the
`-fsanitize=address` requirement instead of reporting a fake negative.
