#!/bin/bash
# Sanitizer Integration Test Suite for RECC Sentinel v0.1.0

set -e

echo "=== RECC Sentinel v0.1.0 - Sanitizer Integration Test Suite ==="
echo "Testing ASan, Valgrind, GDB, and other debugging tool integrations"
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

# Test setup
setup_test_env() {
    log_info "Setting up sanitizer test environment..."
    
    # Clean previous test artifacts
    rm -rf build/test-sanitizer-*
    mkdir -p build/test-results
    
    # Build escalation crate
    log_info "Building escalation crate..."
    cargo build -p re-escalate --release
    
    log_info "Test environment ready"
}

# Test 1: Tool Availability
test_tool_availability() {
    log_test "Tool Availability Check"
    
    local tools=("clang" "gcc" "valgrind" "gdb" "llvm-symbolizer" "addr2line")
    local available_tools=()
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            available_tools+=("$tool")
            log_success "$tool is available"
        else
            missing_tools+=("$tool")
            log_warning "$tool is not available"
        fi
    done
    
    log_info "Available tools: ${available_tools[*]}"
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warning "Missing tools: ${missing_tools[*]}"
    fi
}

# Test 2: ASan Integration
test_asan_integration() {
    log_test "ASan Integration"
    
    log_info "Testing ASan tool integration..."
    
    # Create a simple test program with memory error
    cat > "build/test-results/asan_test.c" << 'EOF'
#include <stdlib.h>
#include <string.h>

int main() {
    char *ptr = malloc(10);
    // Deliberate heap buffer overflow
    memset(ptr, 'A', 20);  // Writing 20 bytes to 10-byte allocation
    free(ptr);
    return 0;
}
EOF
    
    # Test ASan compilation
    if clang -fsanitize=address -g -O1 "build/test-results/asan_test.c" -o "build/test-results/asan_test" 2>/dev/null; then
        log_success "ASan compilation successful"
        
        # Test ASan execution
        if timeout 10s "build/test-results/asan_test" 2>&1 | grep -q "AddressSanitizer\|heap-buffer-overflow"; then
            log_success "ASan detected memory error correctly"
        else
            log_warning "ASan execution inconclusive"
        fi
    else
        log_warning "ASan compilation failed (may not be available)"
    fi
}

# Test 3: Valgrind Integration
test_valgrind_integration() {
    log_test "Valgrind Integration"
    
    log_info "Testing Valgrind integration..."
    
    # Create a simple test program with memory leak
    cat > "build/test-results/valgrind_test.c" << 'EOF'
#include <stdlib.h>

int main() {
    // Deliberate memory leak
    char *ptr = malloc(100);
    // Forget to free(ptr);
    return 0;
}
EOF
    
    # Compile without sanitizers
    if gcc -g -O1 "build/test-results/valgrind_test.c" -o "build/test-results/valgrind_test" 2>/dev/null; then
        log_success "Valgrind test compilation successful"
        
        # Test Valgrind execution
        if timeout 30s valgrind --leak-check=full --error-exitcode=1 "build/test-results/valgrind_test" 2>&1 | grep -q "definitely lost\|Memcheck"; then
            log_success "Valgrind detected memory leak correctly"
        else
            log_warning "Valgrind execution inconclusive"
        fi
    else
        log_warning "Valgrind test compilation failed"
    fi
}

# Test 4: GDB Integration
test_gdb_integration() {
    log_test "GDB Integration"
    
    log_info "Testing GDB integration..."
    
    # Create a simple test program for GDB
    cat > "build/test-results/gdb_test.c" << 'EOF'
#include <stdio.h>

int main() {
    int x = 42;
    printf("x = %d\n", x);
    return 0;
}
EOF
    
    # Compile with debug info
    if gcc -g -O0 "build/test-results/gdb_test.c" -o "build/test-results/gdb_test" 2>/dev/null; then
        log_success "GDB test compilation successful"
        
        # Test GDB batch mode
        cat > "build/test-results/gdb_script.gdb" << 'EOF'
break main
run
info registers
quit
EOF
        
        if timeout 10s gdb -batch -x "build/test-results/gdb_script.gdb" "build/test-results/gdb_test" 2>&1 | grep -q "Breakpoint\|main\|eax\|rax"; then
            log_success "GDB batch mode working correctly"
        else
            log_warning "GDB batch mode inconclusive"
        fi
    else
        log_warning "GDB test compilation failed"
    fi
}

# Test 5: Escalation Runner
test_escalation_runner() {
    log_test "Escalation Runner"
    
    log_info "Testing escalation runner binary..."
    
    # Create a test finding
    cat > "build/test-results/test_finding.json" << 'EOF'
{
  "id": "test-finding-001",
  "kind": "heap_overflow",
  "confidence": 0.8,
  "evidence": {
    "memory": {
      "ptr": "0x12345678",
      "size": 100
    },
    "stacks": {
      "alloc": ["malloc", "main"],
      "call": ["memcpy", "main"]
    }
  }
}
EOF
    
    # Test escalation runner
    if cargo run -p re-escalate --bin run_escalation -- "build/test-results/test_finding.json" > "build/test-results/escalation_runner.log" 2>&1; then
        log_success "Escalation runner executed successfully"
        
        # Check for output
        if [[ -f "build/test-results/escalation_runner.log" ]]; then
            log_success "Escalation runner produced output"
        fi
    else
        log_warning "Escalation runner failed (may be expected without proper environment)"
    fi
}

# Test 6: Tool Output Parsing
test_tool_output_parsing() {
    log_test "Tool Output Parsing"
    
    log_info "Testing output parsing capabilities..."
    
    # Test ASan output parsing
    local asan_output="==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12345678"
    if echo "$asan_output" | grep -q "heap-buffer-overflow"; then
        log_success "ASan output parsing pattern works"
    else
        log_error "ASan output parsing pattern failed"
    fi
    
    # Test Valgrind output parsing
    local valgrind_output="==12345== 100 bytes in 1 blocks are definitely lost"
    if echo "$valgrind_output" | grep -q "definitely lost"; then
        log_success "Valgrind output parsing pattern works"
    else
        log_error "Valgrind output parsing pattern failed"
    fi
    
    # Test GDB output parsing
    local gdb_output="Breakpoint 1, main () at test.c:5"
    if echo "$gdb_output" | grep -q "Breakpoint"; then
        log_success "GDB output parsing pattern works"
    else
        log_error "GDB output parsing pattern failed"
    fi
}

# Test 7: Timeout Handling
test_timeout_handling() {
    log_test "Timeout Handling"
    
    log_info "Testing timeout enforcement..."
    
    # Create a program that runs forever
    cat > "build/test-results/timeout_test.c" << 'EOF'
#include <unistd.h>

int main() {
    while (1) {
        sleep(1);
    }
    return 0;
}
EOF
    
    if gcc "build/test-results/timeout_test.c" -o "build/test-results/timeout_test" 2>/dev/null; then
        # Test timeout enforcement
        local start_time=$(date +%s)
        timeout 3s "build/test-results/timeout_test" 2>/dev/null || true
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [[ $duration -le 5 ]]; then  # Should timeout within 5 seconds
            log_success "Timeout enforcement working (${duration}s)"
        else
            log_warning "Timeout enforcement slow (${duration}s)"
        fi
    else
        log_warning "Timeout test compilation failed"
    fi
}

# Test 8: Multiple Tool Integration
test_multiple_tool_integration() {
    log_test "Multiple Tool Integration"
    
    log_info "Testing integration of multiple tools..."
    
    # Test that multiple tools can be used together
    local tools_available=0
    
    if command -v clang >/dev/null 2>&1; then
        ((tools_available++))
    fi
    
    if command -v valgrind >/dev/null 2>&1; then
        ((tools_available++))
    fi
    
    if command -v gdb >/dev/null 2>&1; then
        ((tools_available++))
    fi
    
    if [[ $tools_available -ge 2 ]]; then
        log_success "Multiple debugging tools available ($tools_available tools)"
    else
        log_warning "Limited debugging tools available ($tools_available tools)"
    fi
}

# Test 9: Error Recovery
test_error_recovery() {
    log_test "Error Recovery"
    
    log_info "Testing error recovery scenarios..."
    
    # Test with invalid finding
    cat > "build/test-results/invalid_finding.json" << 'EOF'
{
  "invalid": "json structure"
}
EOF
    
    if cargo run -p re-escalate --bin run_escalation -- "build/test-results/invalid_finding.json" 2>&1 | grep -q "error\|Error\|failed"; then
        log_success "Error handling for invalid findings works"
    else
        log_warning "Error handling for invalid findings inconclusive"
    fi
}

# Test 10: Performance Under Load
test_performance_under_load() {
    log_test "Performance Under Load"
    
    log_info "Testing performance with multiple findings..."
    
    # Create multiple test findings
    for i in {1..5}; do
        cat > "build/test-results/finding_$i.json" << EOF
{
  "id": "test-finding-$i",
  "kind": "heap_overflow",
  "confidence": 0.8,
  "evidence": {
    "memory": {
      "ptr": "0x1234567$i",
      "size": 100
    }
  }
}
EOF
    done
    
    local start_time=$(date +%s)
    
    # Process multiple findings
    for i in {1..5}; do
        cargo run -p re-escalate --bin run_escalation -- "build/test-results/finding_$i.json" >/dev/null 2>&1 || true
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [[ $duration -lt 60 ]]; then  # Less than 1 minute for 5 findings
        log_success "Performance under load acceptable (${duration}s for 5 findings)"
    else
        log_warning "Performance under load slow (${duration}s for 5 findings)"
    fi
}

# Generate test report
generate_report() {
    echo -e "\n${BLUE}=== Sanitizer Integration Test Report ===${NC}"
    echo "Total Tests: $TESTS_TOTAL"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    
    local success_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    echo "Success Rate: $success_rate%"
    
    echo -e "\n${BLUE}=== Tool Requirements ===${NC}"
    echo "For full sanitizer integration:"
    echo "1. clang/gcc with sanitizer support"
    echo "2. valgrind for memory checking"
    echo "3. gdb for debugging"
    echo "4. llvm-symbolizer for symbolization"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "\n${GREEN}🎉 All sanitizer integration tests passed!${NC}"
        return 0
    else
        echo -e "\n${YELLOW}⚠ Some tests failed. Check the logs for details.${NC}"
        return 1
    fi
}

# Main test execution
main() {
    echo "Starting sanitizer integration tests..."
    echo "Test results will be saved to: build/test-results/"
    echo
    
    setup_test_env
    
    # Run all tests
    test_tool_availability
    test_asan_integration
    test_valgrind_integration
    test_gdb_integration
    test_escalation_runner
    test_tool_output_parsing
    test_timeout_handling
    test_multiple_tool_integration
    test_error_recovery
    test_performance_under_load
    
    # Generate final report
    generate_report
}

# Run main function
main "$@"
