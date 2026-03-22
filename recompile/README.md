# RECC Sentinel v0.1.0

**eBPF-driven compiler companion for C/C++ binaries**

RECC Sentinel is an always-on eBPF-driven compiler companion that monitors C/C++ binaries at runtime for memory, concurrency, and syscall anomalies. Instead of relying solely on Address/Thread/Memory Sanitizers, it classifies errors in real time through kernel-level probes and automatically escalates to the right debugging tool (ASan, TSan, MSan, LSan, Valgrind, or GDB) only when needed.

Each anomaly produces a structured finding, and RECC generates a self-contained "Crashpack" with the minimal repro harness, logs, and fix hints—removing manual triage and making debugging deterministic and repeatable.

## 🚀 Key Features

- **Real-time eBPF Monitoring**: Kernel-level probes for memory, heap, and syscall tracking
- **Intelligent Rule Engine**: Advanced clustering, deduplication, and Top-K selection
- **Automatic Escalation**: Smart escalation to ASan, Valgrind, GDB, and sanitizers
- **Self-contained Crashpacks**: Complete repro harnesses with build scripts
- **Linux-Native First**: Native Linux and Docker are the supported execution paths
- **Production Ready**: Comprehensive CLI with subcommands and error handling

## 📋 Requirements

### System Requirements
- **Linux**: Kernel 4.1+ with BPF support
- **Rust**: 1.70+ for building components

### Linux Native Mode (Optional)
- **CAP_BPF** and **CAP_PERFMON** capabilities
- Unprivileged BPF enabled OR running as root
- BPF JIT compiler enabled (recommended)

## 🛠️ Installation

### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd recompile

# Build all components
cargo build --release

# Build examples
./scripts/build-examples.sh

# Run a native example on Linux
cargo run -p rerun -- run --native build/examples/memcpy_overflow
```

### Development Setup

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y libelf-dev pkg-config clang llvm libbpf-dev

# Build and test
cargo build
cargo test
```

## 🎯 Usage

### Basic Analysis

```bash
# Analyze a binary with eBPF monitoring
cargo run -p rerun -- run examples/memcpy_overflow

# Specify output directory
cargo run -p rerun -- run examples/double_free --output build/my-analysis

# Run with automatic escalation
cargo run -p rerun -- run examples/invalid_free --escalate always
```

### Native Mode (Linux)

```bash
# Run with native eBPF (requires capabilities)
cargo run -p rerun -- run --native examples/memcpy_overflow

# Set capabilities for unprivileged access
sudo setcap 'cap_bpf,cap_perfmon+ep' target/release/rerun
./target/release/rerun run --native examples/memcpy_overflow
```

### Native Mode In Docker

Native eBPF runs in Docker must share the Linux PID namespace with the traced process.
Use both `--privileged` and `--pid=host`:

```bash
docker build -t recompile-bootstrap:host .
docker run --rm -it --privileged --pid=host \
  -v "$PWD":/workspace/recompile \
  recompile-bootstrap:host bash
```

Then, inside the container:

```bash
cd /workspace/recompile/recompile
./target/release/rerun run --native build/examples/memcpy_overflow
```

### Escalation Analysis

```bash
# Run escalation on existing crashpack
cargo run -p rerun -- escalate build/crashpack

# Use specific tool
cargo run -p rerun -- escalate build/crashpack --tool asan
```

### Crashpack Operations

```bash
# View crashpack summary
cargo run -p rerun -- crashpack open build/crashpack

# Validate crashpack structure
cargo run -p rerun -- crashpack validate build/crashpack
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   C/C++ Binary  │    │   eBPF Probes    │    │   Rule Engine   │
│                 │◄───┤                  ├───►│                 │
│  - malloc/free  │    │  - heap_tracker  │    │  - clustering   │
│  - memcpy/str   │    │  - copy_checker  │    │  - dedup        │
│  - syscalls     │    │  - sentinel_extra│    │  - confidence   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Crashpack     │◄───┤  Escalation      │◄───┤   Findings      │
│                 │    │                  │    │                 │
│  - findings.json│    │  - ASan/Valgrind │    │  - heap_overflow│
│  - repro harness│    │  - GDB/debugger  │    │  - double_free  │
│  - build scripts│    │  - sanitizers    │    │  - invalid_free │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Core Components

1. **eBPF Probes** (`runtime/bpf/`)
   - `heap_tracker.bpf.c`: Memory allocation/deallocation tracking
   - `copy_checker.bpf.c`: Buffer overflow detection
   - `sentinel_extra.bpf.c`: I/O and synchronization monitoring

2. **Rule Engine** (`re-rules/`)
   - Advanced clustering and deduplication
   - Confidence scoring and Top-K selection
   - Symbolization with llvm-symbolizer and addr2line

3. **Escalation Engine** (`re-escalate/`)
   - ASan, Valgrind, GDB integration
   - TSan, MSan, UBSan, LSan support
   - Timeout enforcement and output parsing

4. **Harness Generation** (`re-harness/`)
   - Minimal repro harness creation
   - Build script generation with sanitizer flags
   - Template-based C code generation

5. **CLI Interface** (`rerun/`)
   - Subcommand-based interface (`run`, `escalate`, `crashpack`)
   - Native and VM mode support
   - Comprehensive error handling

## 📊 Example Output

### Finding Detection
```json
{
  "schema_version": "1.0",
  "id": "F-heap-overflow-7a155678dfb60aa-1759897311",
  "class": "HeapOverflow",
  "confidence": "High",
  "severity": "Critical",
  "timestamp": 1759897311,
  "pid": 12345,
  "evidence": {
    "memory": {
      "ptr": "0x7f8b4c000000",
      "size": 100
    },
    "stacks": {
      "alloc": ["malloc", "main"],
      "call": ["memcpy", "main"]
    }
  },
  "escalation": {
    "tool": "asan",
    "reason": "High confidence memory error",
    "estimated_cost": "low"
  }
}
```

### Crashpack Structure
```
build/crashpack/
├── findings.json          # Structured findings
├── harnesses/             # Repro harnesses
│   ├── repro_heap_overflow.c
│   └── build.sh
├── escalation/            # Escalation results
│   ├── asan_output.log
│   └── valgrind_output.log
├── manifest.json          # Build metadata
└── README.md              # Summary and usage
```

## 🧪 Testing

### Native Verification
```bash
# Cargo-level verification
cargo check
cargo test -q -p re-rules --lib

# Native Docker golden checks
docker run --rm -it --privileged --pid=host \
  -v "$PWD":/workspace/recompile \
  recompile-bootstrap:host bash
```

### Individual Component Tests
```bash
# Test rule engine clustering
cargo run -p re-rules --bin test_clustering

# Test symbolizer
cargo run -p re-rules --bin test_symbolizer

# Test escalation runner
cargo run -p re-escalate --bin run_escalation -- /path/to/finding.json
```

## 📚 Documentation

- **[QUICKSTART.md](QUICKSTART.md)**: Getting started guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Detailed system architecture
- **[CHANGELOG.md](CHANGELOG.md)**: Version history and changes

## 🔧 Configuration

### Rule Engine Configuration (`re.toml`)
```toml
[clustering]
max_clusters = 100
window_s = 60
top_k = 3
confidence_merge_threshold = 0.8
similarity_threshold = 0.9

[escalation]
timeout_ms = 120000
cooldown_ms = 5000
```

### Escalation Configuration
```toml
[tools.asan]
enabled = true
timeout_ms = 60000
compile_flags = ["-fsanitize=address", "-g", "-O1"]
runtime_flags = ["abort_on_error=1", "detect_leaks=1"]
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Development Workflow
```bash
# Run tests before committing
cargo test
cargo clippy
cargo fmt
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **eBPF Community**: For the powerful kernel programming framework
- **LLVM Project**: For sanitizer and symbolization tools
- **Rust Community**: For the excellent ecosystem and tooling

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/recc-sentinel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/recc-sentinel/discussions)
- **Documentation**: [Project Wiki](https://github.com/your-org/recc-sentinel/wiki)

---

**RECC Sentinel v0.1.0** - Making C/C++ debugging faster, safer, and mostly autonomous.
