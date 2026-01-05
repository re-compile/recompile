# CLAUDE.md - AI Assistant Context for re:compile

This document provides essential context for AI assistants working on this codebase.

## Project Overview

**re:compile** is an AI-native C/C++ debugging toolchain that unifies eBPF-based runtime monitoring, sanitizers (ASan/TSan/MSan/UBSan), and deterministic replay into a single tool with structured JSON output.

### Value Proposition
Traditional debugging requires juggling gdb, Valgrind, and multiple sanitizers. re:compile provides:
- **Fast triage** via eBPF probes (<5% overhead)
- **Intelligent escalation** to sanitizers when needed
- **Unified findings** in one JSON schema for terminal, LSP, CI, and AI agents
- **Crashpacks** with reproducible harnesses

## Current State (Week 1 MVP)

### Working Components
| Component | Location | Status |
|-----------|----------|--------|
| eBPF probes | `recompile/runtime/bpf/` | Functional |
| C agent (re-mini) | `recompile/runtime/agent/re-mini.c` | Functional |
| VM launcher | `recompile/vm-launcher/` | Functional |
| Compiler wrapper | `recompile/recc/` | Functional |
| Event schema | `recompile/runtime/shared/re_events.h` | Complete |

### Needs Implementation
| Component | Location | Status |
|-----------|----------|--------|
| Native Linux mode | `recompile/rerun/src/native.rs` | Stubbed - needs re-mini integration |
| Escalation runners | `recompile/re-escalate/` | Stubbed - ASan/Valgrind/GDB |
| Crashpack writer | `recompile/re-crashpack/` | Stubbed |
| Harness generator | `recompile/re-harness/` | Stubbed |

### Deferred to Phase 2+
- LLVM passes (`llvm-passes/`)
- LSP bridge (`lsp/`)
- MCP server (`protocols/mcp/`)
- Windows support
- ML-based ranking

## Priority Stack (Native Linux MVP)

1. **Native Linux mode** - Get `re run --native ./examples/memcpy_overflow` working in Docker
2. **Validate examples** - memcpy_overflow, double_free, invalid_free
3. **Complete escalation** - Wire ASan into the pipeline
4. **Crashpack generation** - Package findings + repro artifacts
5. **Rule engine cleanup** - JSON-configurable rules (currently hardcoded)

## Key Files to Understand

### Must-Read (Core Pipeline)
```
recompile/runtime/agent/re-mini.c          # C agent - BPF loading, uprobe attachment, event handling (~1200 lines)
recompile/runtime/bpf/heap_tracker.bpf.c   # Tracks malloc/free/calloc/realloc
recompile/runtime/bpf/copy_checker.bpf.c   # Detects memcpy overflows
recompile/runtime/shared/re_events.h       # Event struct definitions (128 bytes)
recompile/runtime/vm/user-data             # Cloud-init that shows the working VM flow
```

### CLI & Orchestration
```
recompile/rerun/src/main.rs                # CLI entry point
recompile/rerun/src/cli.rs                 # Subcommand handlers
recompile/rerun/src/native.rs              # Native mode (needs implementation)
recompile/rerun/src/vm.rs                  # VM mode implementation
recompile/vm-launcher/src/lib.rs           # QEMU launch logic
```

### Rule Engine & Escalation
```
recompile/re-rules/src/engine.rs           # Rule processor
recompile/re-rules/src/rules.rs            # Built-in rules (hardcoded)
recompile/re-rules/src/clustering.rs       # Dedup & Top-K selection
recompile/re-escalate/src/runner.rs        # Tool orchestration (stubbed)
```

## Architecture

### Data Flow (Native Mode Target)
```
Binary Execution
       │
       ▼
┌─────────────────────────────────────────────────────┐
│                    re-mini agent                     │
│  1. Load BPF objects (heap_tracker, copy_checker)   │
│  2. Attach uprobes to libc (malloc, free, memcpy)   │
│  3. Fork/exec target binary (NOT YET IMPLEMENTED)   │
│  4. Consume ringbuf events                          │
│  5. Symbolize stacks (addr2line / llvm-symbolizer)  │
│  6. Emit JSON findings                              │
└─────────────────────────────────────────────────────┘
       │
       ▼
    findings.json
```

### Current VM Flow (Working)
The VM flow works by compiling test programs INSIDE the VM (solving Mach-O vs ELF ABI issues):
```
reseed.sh → Creates cloud-init ISO
re-qemu.sh → Launches QEMU
user-data (inside VM):
  ├── Mount host via 9p
  ├── Build re-mini agent
  ├── Compile test binary INSIDE VM
  ├── Run re-mini with eBPF attached
  └── Output findings to virtio-serial
```

## Known Issues

### native.rs Bugs
1. **References Rust agent** - Comment says "Run the Rust agent" but should use C agent (re-mini)
2. **Unused function** - `has_capability()` function is dead code
3. **Not implemented** - Just prints messages, doesn't actually run re-mini

### re-mini.c Limitations
1. **No fork/exec** - Agent only attaches probes; target binary must be run separately
2. **Hardcoded paths**:
   - `/usr/lib/aarch64-linux-gnu/libc.so.6` (line 34) - ARM64-specific
   - `/host/build/crashpack` (lines 271, 376) - VM-specific path
   - `/dev/virtio-ports/re.findings` (line 40) - VM-specific output

### Hardcoded Paths in Codebase
- `/opt/homebrew/...` - macOS Homebrew paths in vm-launcher, scripts, Makefile
- ARM64 libc paths in user-data and re-mini.c

## Development Environment

### Docker (Recommended for Native Mode)
```bash
# Run with eBPF capabilities
docker run -it --privileged \
  -v $(pwd):/workspace \
  ubuntu:22.04 bash

# Inside container
apt-get update && apt-get install -y \
  build-essential clang llvm \
  libbpf-dev libelf-dev pkg-config \
  linux-tools-$(uname -r)
```

### Building
```bash
cd recompile
cargo build --release

# Build BPF objects (modify Makefile for x86_64 first)
cd runtime/bpf
make clean && make

# Build C agent
cd ../agent
clang -O2 -g -Wall -I../bpf -I../shared \
  -o re-mini re-mini.c -lelf -lz -lbpf -ldl
```

## Testing

### E2E Tests (Priority)
```bash
# Build examples
cd recompile/examples && ./build.sh

# Expected results:
# - memcpy_overflow → heap_overflow finding
# - double_free → double_free finding
# - invalid_free → invalid_free finding
```

### Running the Agent (Current Working Flow Inside VM)
```bash
/usr/local/bin/re-mini \
  --heap /host/runtime/bpf/heap_tracker.bpf.o \
  --obj /host/runtime/bpf/copy_checker.bpf.o \
  --sentinel /host/runtime/bpf/sentinel_extra.bpf.o \
  --binary /tmp/test_binary \
  --libc /lib/x86_64-linux-gnu/libc.so.6 \
  --out /dev/stdout &

# Then run the target
./test_binary
```

## Finding Schema (v1)

```json
{
  "schema_version": "1.0",
  "id": "F-heap-overflow-{hash}-{timestamp}",
  "class": "heap_overflow",
  "confidence": "high",
  "severity": "critical",
  "timestamp": 1234567890,
  "pid": 12345,
  "evidence": {
    "memory": {"ptr": 140000000, "size": 64, "alloc_size": 32, "operation": "memcpy"},
    "stacks": {
      "alloc": ["malloc", "makeBuf", "main"],
      "call": ["memcpy", "fill", "main"]
    }
  },
  "escalation": {
    "tool": "asan",
    "reason": "len > alloc_size",
    "estimated_cost": "low"
  }
}
```

## Confidence Semantics
- `1.0` / `certain` - Deterministic proof (e.g., double free observed)
- `0.8` / `high` - Strong evidence (e.g., memcpy len > alloc_size)
- `0.6` / `medium` - Heuristic hint (e.g., potential UAF)
- `0.4` / `low` - Incomplete evidence, needs escalation

## Commands Reference

```bash
# Compile with recc (adds debug flags + manifest)
recc examples/memcpy_overflow.c -o build/memcpy_overflow

# Run with VM mode (current default)
re run ./build/memcpy_overflow

# Run with native mode (target for this sprint)
re run --native ./build/memcpy_overflow

# Escalate findings
re escalate build/crashpack --tool asan

# View crashpack
re crashpack open build/crashpack
```

## What NOT to Work On (Phase 2+)

- LLVM passes for bounds metadata
- LSP diagnostics integration
- MCP server for AI agents
- Windows support
- rr (record/replay) integration
- ML-based root cause ranking
- Rust agent migration (keep C agent)
