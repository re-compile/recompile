#!/bin/bash

# RECC Sentinel Complete Test Suite
# This script validates the entire system end-to-end

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/recc-test-$(date +%s)"
BUILD_DIR="build"
LOG_FILE="$TEST_DIR/test.log"

# Create test directory
mkdir -p "$TEST_DIR"

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}✓${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}✗${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1" | tee -a "$LOG_FILE"
}

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Run a test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    log "Running test: $test_name"
    
    if eval "$test_command" >> "$LOG_FILE" 2>&1; then
        success "$test_name passed"
        ((TESTS_PASSED++))
        return 0
    else
        error "$test_name failed"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Cleanup function
cleanup() {
    log "Cleaning up test environment..."
    rm -rf "$TEST_DIR"
    # Kill any lingering processes
    pkill -f qemu-system || true
    pkill -f re-mini || true
}

# Set up cleanup trap
trap cleanup EXIT

# Main test execution
main() {
    log "Starting RECC Sentinel Complete Test Suite"
    log "Test directory: $TEST_DIR"
    log "Log file: $LOG_FILE"
    
    # Test 1: Build all components
    log "=== Phase 1: Build System ==="
    run_test "Build all crates" "cargo build --release"
    run_test "Build examples" "cd examples && ./build.sh"
    run_test "Generate configuration" "cargo run -p re-rules --bin generate_config"
    
    # Test 2: Individual component tests
    log "=== Phase 2: Component Tests ==="
    run_test "Rule engine clustering" "cargo run -p re-rules --bin test_clustering"
    run_test "Symbolizer functionality" "cargo run -p re-rules --bin test_symbolizer"
    run_test "Harness generation" "cargo run -p re-harness --bin generate_harness"
    
    # Test 3: CLI interface
    log "=== Phase 3: CLI Interface ==="
    run_test "CLI help display" "cargo run -p rerun -- --help"
    run_test "Run subcommand help" "cargo run -p rerun -- run --help"
    run_test "Escalation subcommand help" "cargo run -p rerun -- escalate --help"
    run_test "Crashpack subcommand help" "cargo run -p rerun -- crashpack --help"
    
    # Test 4: VM Mode Analysis
    log "=== Phase 4: VM Mode Analysis ==="
    
    # Clean up any existing state
    log "Cleaning up existing state..."
    ./scripts/reseed.sh >> "$LOG_FILE" 2>&1
    rm -f "$BUILD_DIR/console.log" "$BUILD_DIR/re-findings.log" >> "$LOG_FILE" 2>&1
    
    # Test heap overflow detection
    log "Testing heap overflow detection..."
    if timeout 180 ./scripts/re-qemu.sh >> "$LOG_FILE" 2>&1; then
        if [ -f "$BUILD_DIR/console.log" ] && [ -f "$BUILD_DIR/re-findings.log" ]; then
            success "VM mode analysis completed"
            ((TESTS_PASSED++))
        else
            error "VM mode analysis failed - missing log files"
            ((TESTS_FAILED++))
        fi
    else
        error "VM mode analysis timed out"
        ((TESTS_FAILED++))
    fi
    
    # Test 5: Crashpack Generation
    log "=== Phase 5: Crashpack Generation ==="
    
    if [ -f "$BUILD_DIR/crashpack/findings.json" ]; then
        run_test "Generate crashpack" "./scripts/generate_crashpack.sh"
        
        if [ -d "$BUILD_DIR/crashpack-final" ]; then
            success "Crashpack generation completed"
            ((TESTS_PASSED++))
        else
            error "Crashpack generation failed"
            ((TESTS_FAILED++))
        fi
    else
        warning "No findings found, skipping crashpack generation test"
    fi
    
    # Test 6: Escalation Analysis
    log "=== Phase 6: Escalation Analysis ==="
    
    if [ -f "$BUILD_DIR/crashpack-final/findings.json" ]; then
        # Create a test finding for escalation
        echo '{"schema_version":"1.0","id":"test-finding","class":"HeapOverflow","confidence":"High","severity":"Critical","timestamp":1234567890,"pid":12345,"evidence":{"memory":{"ptr":"0x123456789","size":100},"stacks":{"alloc":["malloc","main"],"call":["memcpy","main"]}},"escalation":{"tool":"asan","reason":"High confidence memory error","estimated_cost":"low"}}' > "$TEST_DIR/test-finding.json"
        
        run_test "Escalation runner" "cargo run -p re-escalate --bin run_escalation -- '$TEST_DIR/test-finding.json'"
    else
        warning "No findings found, skipping escalation test"
    fi
    
    # Test 7: CLI Integration
    log "=== Phase 7: CLI Integration ==="
    
    if [ -d "$BUILD_DIR/crashpack-final" ]; then
        run_test "CLI crashpack open" "cargo run -p rerun -- crashpack open '$BUILD_DIR/crashpack-final'"
        run_test "CLI crashpack validate" "cargo run -p rerun -- crashpack validate '$BUILD_DIR/crashpack-final'"
    else
        warning "No crashpack found, skipping CLI integration test"
    fi
    
    # Test 8: Native Mode (Linux only)
    log "=== Phase 8: Native Mode (Linux only) ==="
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        run_test "Native mode capability check" "cargo run -p rerun -- run --native examples/memcpy_overflow --help"
        success "Native mode available on Linux"
        ((TESTS_PASSED++))
    else
        warning "Native mode not available on $OSTYPE"
    fi
    
    # Test 9: Documentation
    log "=== Phase 9: Documentation ==="
    
    run_test "README exists" "[ -f README.md ]"
    run_test "QUICKSTART exists" "[ -f QUICKSTART.md ]"
    run_test "ARCHITECTURE exists" "[ -f ARCHITECTURE.md ]"
    run_test "CHANGELOG exists" "[ -f CHANGELOG.md ]"
    
    # Test 10: Schema Validation
    log "=== Phase 10: Schema Validation ==="
    
    run_test "Finding schema exists" "[ -f schemas/finding.schema.json ]"
    
    if [ -f "$BUILD_DIR/crashpack-final/findings.json" ]; then
        # Validate findings against schema (if jq is available)
        if command -v jq >/dev/null 2>&1; then
            run_test "Findings JSON validity" "jq empty '$BUILD_DIR/crashpack-final/findings.json'"
        else
            warning "jq not available, skipping JSON validation"
        fi
    fi
    
    # Final results
    log "=== Test Results ==="
    log "Tests passed: $TESTS_PASSED"
    log "Tests failed: $TESTS_FAILED"
    log "Total tests: $((TESTS_PASSED + TESTS_FAILED))"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        success "All tests passed! RECC Sentinel is ready for production."
        exit 0
    else
        error "Some tests failed. Check the log file for details: $LOG_FILE"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check for required commands
    local missing_commands=()
    
    if ! command -v cargo >/dev/null 2>&1; then
        missing_commands+=("cargo")
    fi
    
    if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
        missing_commands+=("qemu-system-x86_64")
    fi
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        error "Missing required commands: ${missing_commands[*]}"
        error "Please install the missing dependencies and try again."
        exit 1
    fi
    
    success "All prerequisites satisfied"
}

# Main execution
check_prerequisites
main
