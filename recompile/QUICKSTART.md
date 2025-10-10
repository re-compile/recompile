# RECC Sentinel Quickstart Guide

Get up and running with RECC Sentinel in 5 minutes!

## 🚀 Prerequisites

- **Linux** (Ubuntu 20.04+ recommended) or **macOS** for development
- **Rust** 1.70+ installed
- **QEMU** (for VM mode)
- **Git**

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y qemu-system-x86 libelf-dev pkg-config
```

**macOS:**
```bash
brew install qemu libelf pkg-config
```

## 📦 Installation

```bash
# Clone and build
git clone <repository-url>
cd recompile
cargo build --release

# Verify installation
cargo run -p rerun -- --help
```

## 🎯 Your First Analysis

### 1. Run a Simple Example

```bash
# Analyze a heap overflow example
cargo run -p rerun -- run examples/memcpy_overflow

# Check the results
ls build/crashpack/
cat build/crashpack/README.md
```

### 2. View the Crashpack

```bash
# Open crashpack summary
cargo run -p rerun -- crashpack open build/crashpack

# View findings
cat build/crashpack/findings.json | jq .
```

### 3. Run with Escalation

```bash
# Analyze with automatic escalation to ASan
cargo run -p rerun -- run examples/double_free --escalate always

# Check escalation results
ls build/crashpack/escalation/
```

## 🔧 Advanced Usage

### Native Mode (Linux Only)

```bash
# Run with native eBPF (faster, requires capabilities)
sudo setcap 'cap_bpf,cap_perfmon+ep' target/release/rerun
cargo run -p rerun -- run --native examples/memcpy_overflow
```

### Custom Output Directory

```bash
# Specify custom output location
cargo run -p rerun -- run examples/invalid_free --output /tmp/my-analysis
```

### Escalation Options

```bash
# Use specific tool
cargo run -p rerun -- escalate build/crashpack --tool valgrind

# Run escalation on existing findings
cargo run -p rerun -- escalate build/crashpack
```

## 🧪 Test Examples

RECC Sentinel comes with several example programs to test different memory errors:

```bash
# Build all examples
cd examples && ./build.sh

# Test heap overflow detection
cargo run -p rerun -- run examples/memcpy_overflow

# Test double free detection  
cargo run -p rerun -- run examples/double_free

# Test invalid free detection
cargo run -p rerun -- run examples/invalid_free
```

## 📊 Understanding Output

### Finding Structure
Each finding contains:
- **Class**: Type of anomaly (HeapOverflow, DoubleFree, InvalidFree)
- **Confidence**: Detection confidence (High, Medium, Low)
- **Severity**: Impact severity (Critical, High, Medium, Low)
- **Evidence**: Memory addresses, stack traces, call sites
- **Escalation**: Recommended debugging tool and reasoning

### Crashpack Contents
- `findings.json`: All detected anomalies
- `harnesses/`: Minimal repro harnesses
- `escalation/`: Results from debugging tools
- `manifest.json`: Build and environment metadata
- `README.md`: Human-readable summary

## 🚨 Troubleshooting

### Common Issues

**"Permission denied" errors:**
```bash
# Set capabilities for native mode
sudo setcap 'cap_bpf,cap_perfmon+ep' target/release/rerun
```

**QEMU not found:**
```bash
# Install QEMU
sudo apt-get install qemu-system-x86  # Ubuntu
brew install qemu                     # macOS
```

**No findings detected:**
```bash
# Check if binary has debug symbols
file examples/memcpy_overflow
readelf -S examples/memcpy_overflow | grep debug

# Rebuild with debug info
cd examples && ./build.sh
```

**VM timeout issues:**
```bash
# Increase timeout in scripts
# Edit re-qemu.sh and change timeout value
```

### Debug Mode

```bash
# Enable verbose logging
RUST_LOG=debug cargo run -p rerun -- run examples/memcpy_overflow

# Check individual components
cargo run -p re-rules --bin test_clustering
cargo run -p re-escalate --bin run_escalation -- /path/to/finding.json
```

## 🎓 Next Steps

1. **Read the Architecture**: Check out [ARCHITECTURE.md](ARCHITECTURE.md)
2. **Configure Rules**: Customize detection in `re.toml`
3. **Integrate with CI**: Add to your build pipeline
4. **Extend Rules**: Add custom detection patterns
5. **Join Community**: Contribute and get support

## 📚 Additional Resources

- **Full Documentation**: [README.md](README.md)
- **Architecture Deep Dive**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Configuration Reference**: [re.toml.example](re.toml.example)
- **Example Programs**: [examples/](examples/)

## 💡 Tips

- **Start Simple**: Begin with the provided examples
- **Use VM Mode**: More reliable for initial testing
- **Check Logs**: Always review `console.log` and `re-findings.log`
- **Validate Results**: Use `crashpack validate` to check output
- **Performance**: Native mode is faster but requires Linux capabilities

---

**Ready to dive deeper?** Check out the [full documentation](README.md) and [architecture guide](ARCHITECTURE.md)!
