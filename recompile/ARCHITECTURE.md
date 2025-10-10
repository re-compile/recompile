# RECC Sentinel Architecture

This document provides a comprehensive overview of RECC Sentinel's architecture, components, and design decisions.

## 🏗️ System Overview

RECC Sentinel is built as a modular eBPF-driven runtime analysis system with the following key principles:

- **Kernel-level monitoring** via eBPF for zero-overhead observation
- **Intelligent escalation** to appropriate debugging tools
- **Self-contained outputs** in the form of crashpacks
- **Production-ready** CLI with comprehensive error handling

## 📊 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        RECC Sentinel                            │
├─────────────────────────────────────────────────────────────────┤
│  CLI Interface (rerun)                                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │
│  │    run      │ │  escalate   │ │  crashpack  │               │
│  └─────────────┘ └─────────────┘ └─────────────┘               │
├─────────────────────────────────────────────────────────────────┤
│  Execution Modes                                                │
│  ┌─────────────┐                     ┌─────────────┐            │
│  │ Native Mode │                     │   VM Mode   │            │
│  │ (Linux only)│                     │ (QEMU/KVM)  │            │
│  └─────────────┘                     └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│  Core Components                                                │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │   eBPF      │ │    Rule     │ │ Escalation  │ │   Harness   ││
│  │   Probes    │ │   Engine    │ │   Engine    │ │  Generator  ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Kernel Space (eBPF)                                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │
│  │heap_tracker │ │copy_checker │ │sentinel_extra│               │
│  └─────────────┘ └─────────────┘ └─────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Component Architecture

### 1. eBPF Probes (`runtime/bpf/`)

**Purpose**: Kernel-level monitoring of memory operations and syscalls.

**Components**:
- **`heap_tracker.bpf.c`**: Monitors `malloc`, `free`, `calloc`, `realloc`
- **`copy_checker.bpf.c`**: Detects buffer overflows in `memcpy`, `strcpy`, etc.
- **`sentinel_extra.bpf.c`**: Monitors I/O operations and synchronization

**Key Features**:
- LRU hash maps for allocation tracking
- Ring buffer for event communication
- Stack trace capture
- Minimal performance overhead

**Data Flow**:
```
Memory Operation → eBPF Probe → Hash Map Lookup → Event Generation → Ring Buffer
```

### 2. Rule Engine (`re-rules/`)

**Purpose**: Intelligent analysis and classification of runtime events.

**Architecture**:
```
Events → Clustering → Deduplication → Confidence Scoring → Top-K Selection → Findings
```

**Key Components**:

#### Clustering Engine
- **Fingerprinting**: Creates unique signatures for similar events
- **Deduplication**: Merges identical or highly similar findings
- **Confidence Merging**: Combines confidence scores from related events
- **Top-K Selection**: Prioritizes the most important findings

#### Symbolization
- **LLVM Symbolizer**: Primary symbolization engine
- **Addr2line**: Fallback symbolization
- **Composite Symbolizer**: Combines multiple sources
- **Caching**: Reduces symbolization overhead

#### Configuration
```toml
[clustering]
max_clusters = 100
window_s = 60
top_k = 3
confidence_merge_threshold = 0.8
similarity_threshold = 0.9
```

### 3. Escalation Engine (`re-escalate/`)

**Purpose**: Automatic escalation to appropriate debugging tools.

**Tool Pipeline**:
```
Finding → Tool Selection → Execution → Output Parsing → Structured Results
```

**Supported Tools**:
- **ASan**: Address sanitizer for memory errors
- **Valgrind**: Comprehensive memory analysis
- **GDB**: Interactive debugging with breakpoints
- **TSan**: Thread sanitizer for concurrency issues
- **MSan**: Memory sanitizer for uninitialized reads
- **UBSan**: Undefined behavior sanitizer
- **LSan**: Leak sanitizer for memory leaks

**Escalation Logic**:
```rust
match finding.class {
    HeapOverflow | DoubleFree | InvalidFree => Tool::Asan,
    UseAfterFree => Tool::Valgrind,
    RaceCondition => Tool::Tsan,
    UninitializedRead => Tool::Msan,
    UndefinedBehavior => Tool::Ubsan,
    MemoryLeak => Tool::Lsan,
    _ => Tool::Gdb,
}
```

### 4. Harness Generator (`re-harness/`)

**Purpose**: Generate minimal repro harnesses for findings.

**Template System**:
- **Handlebars**: Template engine for C code generation
- **Build Scripts**: Automatic sanitizer flag injection
- **Validation**: Ensures harnesses compile and reproduce issues

**Generated Artifacts**:
- `repro_<finding_class>.c`: Minimal C code reproducing the issue
- `build.sh`: Build script with appropriate sanitizer flags
- `README.md`: Instructions for running the harness

### 5. CLI Interface (`rerun/`)

**Purpose**: User-facing interface for all RECC Sentinel operations.

**Subcommands**:
- **`run`**: Analyze binaries with eBPF monitoring
- **`escalate`**: Run escalation on existing findings
- **`crashpack`**: Manage and validate crashpacks

**Execution Modes**:
- **Native Mode**: Direct eBPF execution on Linux
- **VM Mode**: Isolated execution in QEMU microVM

## 🔄 Data Flow

### 1. Analysis Pipeline

```
Binary Execution → eBPF Events → Rule Engine → Findings → Escalation → Crashpack
```

**Detailed Flow**:
1. **Binary Launch**: Target binary starts execution
2. **eBPF Attachment**: Probes attach to relevant functions
3. **Event Generation**: Memory operations trigger eBPF events
4. **Ring Buffer**: Events flow to userspace via ring buffer
5. **Rule Processing**: Rule engine analyzes and clusters events
6. **Finding Generation**: Structured findings created
7. **Escalation**: Appropriate debugging tools executed
8. **Crashpack Creation**: All artifacts packaged together

### 2. VM Mode Flow

```
Host → QEMU Launch → VM Boot → Agent Start → Binary Execution → Findings → Virtio → Host
```

**VM Components**:
- **Cloud-init**: VM configuration and setup
- **Agent**: C-based eBPF agent (`re-mini.c`)
- **Virtio**: Communication channel to host
- **Mounted Storage**: Shared filesystem for findings

### 3. Native Mode Flow

```
Binary → eBPF Probes → Userspace Agent → Rule Engine → Findings → Escalation
```

**Requirements**:
- Linux kernel 4.1+ with BPF support
- CAP_BPF and CAP_PERFMON capabilities
- Unprivileged BPF enabled (optional)

## 📁 File Structure

```
recompile/
├── runtime/
│   ├── bpf/                 # eBPF programs
│   │   ├── heap_tracker.bpf.c
│   │   ├── copy_checker.bpf.c
│   │   └── sentinel_extra.bpf.c
│   ├── agent/               # C userspace agent
│   │   └── re-mini.c
│   └── vm/                  # VM configuration
│       └── user-data
├── re-rules/                # Rule engine
│   ├── src/
│   │   ├── lib.rs
│   │   ├── engine.rs
│   │   ├── clustering.rs
│   │   ├── symbolizer.rs
│   │   └── config.rs
│   └── Cargo.toml
├── re-escalate/             # Escalation engine
│   ├── src/
│   │   ├── lib.rs
│   │   ├── runner.rs
│   │   ├── tools.rs
│   │   └── config.rs
│   └── Cargo.toml
├── re-harness/              # Harness generator
│   ├── src/
│   │   ├── lib.rs
│   │   └── bin/
│   ├── templates/
│   └── Cargo.toml
├── rerun/                   # CLI interface
│   ├── src/
│   │   ├── main.rs
│   │   ├── cli.rs
│   │   ├── native.rs
│   │   └── vm.rs
│   └── Cargo.toml
├── examples/                # Test programs
├── scripts/                 # Automation scripts
└── schemas/                 # JSON schemas
```

## 🔒 Security Considerations

### VM Isolation
- **QEMU MicroVM**: Complete isolation from host
- **Read-only mounts**: VM cannot modify host filesystem
- **Network isolation**: No network access by default
- **Resource limits**: CPU and memory constraints

### Native Mode Security
- **Capability-based**: Uses Linux capabilities instead of root
- **BPF restrictions**: Limited to safe BPF operations
- **Sandboxing**: Process isolation and resource limits
- **Audit logging**: All operations logged

### Data Handling
- **No sensitive data**: Only binary analysis, no source code access
- **Local processing**: All analysis happens locally
- **Temporary files**: Cleanup of temporary artifacts
- **Log sanitization**: Removal of sensitive information

## ⚡ Performance Characteristics

### eBPF Overhead
- **Memory tracking**: <1% CPU overhead
- **Syscall monitoring**: <0.5% CPU overhead
- **Ring buffer**: Minimal memory footprint
- **Hash maps**: O(1) lookup time

### Clustering Performance
- **Fingerprinting**: O(n) where n = number of events
- **Deduplication**: O(n log n) for similarity comparison
- **Top-K selection**: O(n log k) using heap
- **Memory usage**: O(k) where k = max_clusters

### Escalation Performance
- **Tool execution**: Varies by tool (ASan: fast, Valgrind: slow)
- **Timeout enforcement**: Prevents runaway processes
- **Parallel execution**: Multiple tools can run simultaneously
- **Caching**: Symbolization results cached

## 🧪 Testing Strategy

### Unit Tests
- **Rule engine**: Clustering and deduplication logic
- **Symbolization**: Address resolution accuracy
- **Escalation**: Tool execution and output parsing
- **Harness generation**: Template rendering and compilation

### Integration Tests
- **End-to-end**: Complete pipeline testing
- **VM mode**: QEMU integration and communication
- **Native mode**: Capability checking and eBPF execution
- **Example programs**: Known memory error detection

### Performance Tests
- **Overhead measurement**: CPU and memory usage
- **Scalability**: Large binary analysis
- **Timeout handling**: Long-running tool execution
- **Resource limits**: Memory and CPU constraints

## 🔮 Future Architecture

### Planned Enhancements
- **Distributed analysis**: Multi-node processing
- **Cloud integration**: AWS/GCP deployment
- **Real-time streaming**: Live analysis dashboard
- **ML integration**: Anomaly detection and classification

### Extensibility
- **Plugin system**: Custom rule and tool plugins
- **API interface**: REST/GraphQL APIs
- **Webhook integration**: CI/CD pipeline integration
- **Custom schemas**: Extensible finding formats

---

This architecture provides a solid foundation for runtime C/C++ analysis while maintaining performance, security, and extensibility.
