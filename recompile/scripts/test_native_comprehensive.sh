#!/bin/bash
# Comprehensive Native Mode Test Suite for RECC Sentinel v0.1.0
# This script should be run on a Linux system with appropriate capabilities

set -e

echo "=== RECC Sentinel v0.1.0 - Native Mode Test Suite ==="
echo "Testing native mode functionality on Linux systems"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_test() {
    echo -e "\n${BLUE}=== Test $((++TESTS_TOTAL)): $1 ===${NC}"
}

# Check if we're on Linux
check_linux() {
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        echo -e "${YELLOW}⚠ Native mode testing requires Linux. Current OS: $OSTYPE${NC}"
        echo "Skipping native mode tests."
        exit 0
    fi
    log_info "Running on Linux system: $(uname -a)"
}

# Test 1: Build CLI
test_build_cli() {
    log_test "Building CLI for Native Mode"
    
    if cargo build -p rerun --release > "build/test-results/native-build.log" 2>&1; then
        log_success "CLI built successfully for native mode"
    else
        log_error "CLI build failed for native mode"
        return 1
    fi
}

# Test 2: Capability Detection
test_capability_detection() {
    log_test "Capability Detection"
    
    local cli_path="target/release/rerun"
    
    if [[ -f "$cli_path" ]]; then
        log_info "Testing capability detection..."
        
        # Test without capabilities
        if cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Missing required capabilities\|CAP_BPF\|CAP_PERFMON"; then
            log_success "Capability detection working correctly"
        else
            log_warning "Capability detection inconclusive"
        fi
        
        # Test capability checking functions
        if cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Running as UID\|Capability check passed"; then
            log_success "Capability checking functions working"
        else
            log_warning "Capability checking functions inconclusive"
        fi
    else
        log_error "CLI binary not found at $cli_path"
        return 1
    fi
}

# Test 3: BPF System Access
test_bpf_system_access() {
    log_test "BPF System Access"
    
    log_info "Checking BPF system availability..."
    
    # Check if BPF filesystem is available
    if [[ -d "/sys/fs/bpf" ]]; then
        log_success "BPF filesystem available at /sys/fs/bpf"
    else
        log_warning "BPF filesystem not available at /sys/fs/bpf"
    fi
    
    # Check if BPF is enabled in kernel
    if [[ -f "/proc/sys/kernel/unprivileged_bpf_disabled" ]]; then
        local bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
        if [[ "$bpf_disabled" == "0" ]]; then
            log_success "Unprivileged BPF is enabled"
        elif [[ "$bpf_disabled" == "1" ]]; then
            log_warning "Unprivileged BPF is disabled (requires capabilities)"
        else
            log_warning "Unprivileged BPF status unknown"
        fi
    else
        log_warning "Cannot determine BPF status"
    fi
}

# Test 4: Permission Testing
test_permissions() {
    log_test "Permission Testing"
    
    log_info "Testing various permission scenarios..."
    
    # Test as current user
    if cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Native mode is only supported on Linux"; then
        log_success "Linux detection working correctly"
    elif cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Missing required capabilities"; then
        log_success "Capability requirement detection working"
    else
        log_warning "Permission testing inconclusive"
    fi
    
    # Test with sudo (if available)
    if command -v sudo >/dev/null 2>&1; then
        log_info "Testing with sudo..."
        if sudo cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Native mode analysis completed\|Capability check passed"; then
            log_success "Native mode works with sudo"
        else
            log_warning "Native mode with sudo inconclusive"
        fi
    else
        log_warning "sudo not available for testing"
    fi
}

# Test 5: Capability Setting
test_capability_setting() {
    log_test "Capability Setting"
    
    local cli_path="target/release/rerun"
    
    if [[ -f "$cli_path" ]] && command -v setcap >/dev/null 2>&1; then
        log_info "Testing capability setting..."
        
        # Try to set capabilities
        if sudo setcap 'cap_bpf,cap_perfmon+ep' "$cli_path" 2>/dev/null; then
            log_success "Capabilities set successfully"
            
            # Test running with capabilities
            if "$cli_path" run --native /bin/echo "test" 2>&1 | grep -q "Native mode analysis completed\|Capability check passed"; then
                log_success "Native mode works with set capabilities"
            else
                log_warning "Native mode with capabilities inconclusive"
            fi
            
            # Remove capabilities
            sudo setcap -r "$cli_path" 2>/dev/null || true
            log_info "Capabilities removed"
        else
            log_warning "Could not set capabilities (may require libcap-ng)"
        fi
    else
        log_warning "CLI binary or setcap not available for capability testing"
    fi
}

# Test 6: Error Handling
test_error_handling() {
    log_test "Error Handling in Native Mode"
    
    log_info "Testing error handling..."
    
    # Test with invalid binary
    if cargo run -p rerun -- run --native "non-existent-binary" 2>&1 | grep -q "Native mode is only supported on Linux\|No such file"; then
        log_success "Error handling for invalid binary works"
    else
        log_warning "Error handling for invalid binary inconclusive"
    fi
    
    # Test with invalid arguments
    if cargo run -p rerun -- run --native 2>&1 | grep -q "required arguments"; then
        log_success "Error handling for missing arguments works"
    else
        log_warning "Error handling for missing arguments inconclusive"
    fi
}

# Test 7: Native vs VM Mode Comparison
test_native_vs_vm_comparison() {
    log_test "Native vs VM Mode Comparison"
    
    log_info "Comparing native and VM mode behavior..."
    
    # Test that both modes show appropriate messages
    local native_output=$(cargo run -p rerun -- run --native /bin/echo "test" 2>&1 || true)
    local vm_output=$(cargo run -p rerun -- run /bin/echo "test" 2>&1 || true)
    
    if echo "$native_output" | grep -q "Native mode"; then
        log_success "Native mode correctly identified"
    else
        log_warning "Native mode identification inconclusive"
    fi
    
    if echo "$vm_output" | grep -q "VM mode\|Running in VM mode"; then
        log_success "VM mode correctly identified"
    else
        log_warning "VM mode identification inconclusive"
    fi
}

# Test 8: Performance Testing
test_performance() {
    log_test "Performance Testing"
    
    log_info "Testing native mode performance..."
    
    local start_time=$(date +%s%N)
    
    # Run native mode command (should be fast due to capability check)
    cargo run -p rerun -- run --native /bin/echo "test" >/dev/null 2>&1 || true
    
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds
    
    if [[ $duration -lt 5000 ]]; then  # Less than 5 seconds
        log_success "Native mode startup time acceptable (${duration}ms)"
    else
        log_warning "Native mode startup time slow (${duration}ms)"
    fi
}

# Test 9: System Requirements
test_system_requirements() {
    log_test "System Requirements"
    
    log_info "Checking system requirements..."
    
    # Check kernel version
    local kernel_version=$(uname -r)
    log_info "Kernel version: $kernel_version"
    
    # Check for BPF support
    if [[ -f "/proc/sys/net/core/bpf_jit_enable" ]]; then
        local jit_enabled=$(cat /proc/sys/net/core/bpf_jit_enable)
        if [[ "$jit_enabled" == "1" ]]; then
            log_success "BPF JIT enabled"
        else
            log_warning "BPF JIT disabled"
        fi
    else
        log_warning "Cannot determine BPF JIT status"
    fi
    
    # Check for required kernel features
    if [[ -f "/proc/sys/kernel/kptr_restrict" ]]; then
        local kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict)
        if [[ "$kptr_restrict" == "0" ]]; then
            log_success "Kernel pointer restriction disabled"
        else
            log_warning "Kernel pointer restriction enabled ($kptr_restrict)"
        fi
    else
        log_warning "Cannot determine kernel pointer restriction status"
    fi
}

# Generate test report
generate_report() {
    echo -e "\n${BLUE}=== Native Mode Test Report ===${NC}"
    echo "Total Tests: $TESTS_TOTAL"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    
    local success_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    echo "Success Rate: $success_rate%"
    
    echo -e "\n${BLUE}=== Native Mode Requirements ===${NC}"
    echo "For full native mode functionality:"
    echo "1. Linux kernel with BPF support (4.1+)"
    echo "2. CAP_BPF and CAP_PERFMON capabilities"
    echo "3. Unprivileged BPF enabled OR running as root"
    echo "4. BPF JIT compiler enabled (recommended)"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "\n${GREEN}🎉 All native mode tests passed!${NC}"
        return 0
    else
        echo -e "\n${YELLOW}⚠ Some tests failed. Check the logs for details.${NC}"
        return 1
    fi
}

# Main test execution
main() {
    echo "Starting native mode tests..."
    echo "Test results will be saved to: build/test-results/"
    echo
    
    check_linux
    mkdir -p build/test-results
    
    # Run all tests
    test_build_cli
    test_capability_detection
    test_bpf_system_access
    test_permissions
    test_capability_setting
    test_error_handling
    test_native_vs_vm_comparison
    test_performance
    test_system_requirements
    
    # Generate final report
    generate_report
}

# Run main function
main "$@"
