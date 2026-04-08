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

Validated native findings in Docker:

- `memcpy_overflow` -> `heap_overflow`
- `double_free` -> `double_free`
- `invalid_free` -> `invalid_free`

Current priority is Phase 1: turn the working Linux-native path into a clean MVP release candidate.

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
./scripts/validate-phase1.sh
```

## Repo Layout

- `recompile/` - active Rust/C workspace
- `ROADMAP.md` - current roadmap
- `ISSUES_DISCUSSION.md` - current issue/status doc
- `Dockerfile` - supported bootstrap image

## Core Docs

- [`recompile/README.md`](recompile/README.md)
- [`recompile/QUICKSTART.md`](recompile/QUICKSTART.md)
- [`recompile/ARCHITECTURE.md`](recompile/ARCHITECTURE.md)
- [`ROADMAP.md`](ROADMAP.md)
- [`ISSUES_DISCUSSION.md`](ISSUES_DISCUSSION.md)

## Not In Scope Right Now

- VM-first workflow
- macOS-first support
- Rust runtime agent
- `recc` as a required MVP path
- CI as a release gate

## Phase 1 Baseline

The current release-candidate regression command is:

```bash
cd recompile
./scripts/validate-phase1.sh
```
