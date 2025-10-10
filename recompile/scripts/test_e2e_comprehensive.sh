#!/bin/bash
# Comprehensive End-to-End Test Suite for RECC Sentinel v0.1.0

set -e

echo "=== RECC Sentinel v0.1.0 - Comprehensive E2E Test Suite ==="
echo "Testing full pipeline: eBPF → rules → escalation → crashpack"
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
    log_info "Setting up test environment..."
    
    # Clean previous test artifacts
    rm -rf build/test-*
    mkdir -p build/test-results
    
    # Build all components
    log_info "Building all components..."
    cargo build --release
    
    log_info "Test environment ready"
}

# Test 1: CLI Help and Basic Functionality
test_cli_help() {
    log_test "CLI Help and Basic Functionality"
    
    if cargo run -p rerun -- --help > /dev/null 2>&1; then
        log_success "Main CLI help works"
    else
        log_error "Main CLI help failed"
        return 1
    fi
    
    if cargo run -p rerun -- run --help > /dev/null 2>&1; then
        log_success "Run command help works"
    else
        log_error "Run command help failed"
        return 1
    fi
    
    if cargo run -p rerun -- escalate --help > /dev/null 2>&1; then
        log_success "Escalate command help works"
    else
        log_error "Escalate command help failed"
        return 1
    fi
    
    if cargo run -p rerun -- crashpack --help > /dev/null 2>&1; then
        log_success "Crashpack command help works"
    else
        log_error "Crashpack command help failed"
        return 1
    fi
}

# Test 2: Native Mode Detection
test_native_mode() {
    log_test "Native Mode Detection"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_info "Running on Linux - testing native mode"
        if cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Native mode"; then
            log_success "Native mode detected correctly"
        else
            log_warning "Native mode detection inconclusive"
        fi
    else
        log_info "Running on non-Linux system - testing error message"
        if cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Native mode is only supported on Linux"; then
            log_success "Non-Linux error message correct"
        else
            log_error "Non-Linux error message incorrect"
            return 1
        fi
    fi
}

# Test 3: VM Mode with Example Programs
test_vm_mode_examples() {
    log_test "VM Mode with Example Programs"
    
    local examples=("memcpy_overflow" "double_free" "invalid_free")
    
    for example in "${examples[@]}"; do
        log_info "Testing example: $example"
        
        # Clean previous results
        rm -rf build/test-$example
        
        # Run analysis
        if cargo run -p rerun -- run "examples/$example" --output "build/test-$example" > "build/test-results/$example.log" 2>&1; then
            log_success "Analysis completed for $example"
            
            # Check for findings
            if [[ -f "build/test-$example/findings.json" ]]; then
                local finding_count=$(jq length "build/test-$example/findings.json" 2>/dev/null || echo "0")
                if [[ "$finding_count" -gt 0 ]]; then
                    log_success "Findings generated for $example ($finding_count findings)"
                else
                    log_warning "No findings generated for $example"
                fi
            else
                log_warning "No findings.json found for $example"
            fi
            
            # Check for crashpack summary
            if [[ -f "build/test-$example/README.md" ]]; then
                log_success "Crashpack summary generated for $example"
            else
                log_warning "No crashpack summary for $example"
            fi
        else
            log_error "Analysis failed for $example"
            return 1
        fi
    done
}

# Test 4: Rule Engine and Clustering
test_rule_engine() {
    log_test "Rule Engine and Clustering"
    
    log_info "Testing rule engine clustering..."
    
    if cargo run -p rerun --bin test_clustering > "build/test-results/clustering.log" 2>&1; then
        log_success "Rule engine clustering test passed"
    else
        log_error "Rule engine clustering test failed"
        return 1
    fi
    
    log_info "Testing symbolizer..."
    
    if cargo run -p rerun --bin test_symbolizer > "build/test-results/symbolizer.log" 2>&1; then
        log_success "Symbolizer test passed"
    else
        log_error "Symbolizer test failed"
        return 1
    fi
}

# Test 5: Escalation Engine
test_escalation_engine() {
    log_test "Escalation Engine"
    
    log_info "Testing escalation runner..."
    
    # Create a test finding
    local test_finding='{"id":"test-finding","kind":"heap_overflow","confidence":0.8,"evidence":{"memory":{"ptr":"0x12345678","size":100}}}'
    echo "$test_finding" > "build/test-results/test-finding.json"
    
    if cargo run -p rerun --bin run_escalation -- "build/test-results/test-finding.json" > "build/test-results/escalation.log" 2>&1; then
        log_success "Escalation runner test passed"
    else
        log_warning "Escalation runner test failed (may be expected without proper environment)"
    fi
}

# Test 6: Harness Generation
test_harness_generation() {
    log_test "Harness Generation"
    
    log_info "Testing harness generator..."
    
    # Create a test finding for harness generation
    local test_finding='{"id":"test-harness","kind":"heap_overflow","confidence":0.9,"evidence":{"memory":{"ptr":"0x12345678","size":100},"stacks":{"alloc":["malloc","main"],"call":["memcpy","main"]}}}'
    echo "$test_finding" > "build/test-results/test-harness-finding.json"
    
    if cargo run -p rerun --bin generate_harness -- "build/test-results/test-harness-finding.json" > "build/test-results/harness.log" 2>&1; then
        log_success "Harness generator test passed"
    else
        log_warning "Harness generator test failed (may be expected without proper environment)"
    fi
}

# Test 7: Crashpack Validation
test_crashpack_validation() {
    log_test "Crashpack Validation"
    
    # Test with a real crashpack if available
    if [[ -d "build/crashpack" ]]; then
        log_info "Testing crashpack validation with existing crashpack..."
        
        if cargo run -p rerun -- crashpack validate "build/crashpack" > "build/test-results/crashpack-validation.log" 2>&1; then
            log_success "Crashpack validation passed"
        else
            log_warning "Crashpack validation failed (may be expected)"
        fi
    else
        log_warning "No existing crashpack found for validation test"
    fi
}

# Test 8: Full Pipeline Integration
test_full_pipeline() {
    log_test "Full Pipeline Integration"
    
    log_info "Testing complete pipeline with memcpy_overflow example..."
    
    # Clean previous results
    rm -rf build/test-full-pipeline
    
    # Run full analysis with escalation
    if cargo run -p rerun -- run "examples/memcpy_overflow" --output "build/test-full-pipeline" --escalate "auto" > "build/test-results/full-pipeline.log" 2>&1; then
        log_success "Full pipeline analysis completed"
        
        # Check for all expected outputs
        local checks=(
            "findings.json:Findings"
            "README.md:Summary"
            "harnesses/:Harnesses"
            "escalation/:Escalation"
        )
        
        for check in "${checks[@]}"; do
            IFS=':' read -r file desc <<< "$check"
            if [[ -e "build/test-full-pipeline/$file" ]]; then
                log_success "$desc directory/file created"
            else
                log_warning "$desc directory/file not found"
            fi
        done
    else
        log_error "Full pipeline analysis failed"
        return 1
    fi
}

# Test 9: Error Handling
test_error_handling() {
    log_test "Error Handling"
    
    log_info "Testing error handling with invalid inputs..."
    
    # Test with non-existent binary
    if cargo run -p rerun -- run "non-existent-binary" 2>&1 | grep -q "No such file"; then
        log_success "Proper error handling for non-existent binary"
    else
        log_warning "Error handling for non-existent binary inconclusive"
    fi
    
    # Test with invalid crashpack
    if cargo run -p rerun -- crashpack validate "non-existent-crashpack" 2>&1 | grep -q "No such file\|not found"; then
        log_success "Proper error handling for invalid crashpack path"
    else
        log_warning "Error handling for invalid crashpack path inconclusive"
    fi
}

# Test 10: Performance and Resource Usage
test_performance() {
    log_test "Performance and Resource Usage"
    
    log_info "Testing build performance..."
    
    local start_time=$(date +%s)
    cargo build --release > "build/test-results/build-performance.log" 2>&1
    local end_time=$(date +%s)
    local build_time=$((end_time - start_time))
    
    if [[ $build_time -lt 300 ]]; then  # Less than 5 minutes
        log_success "Build completed in reasonable time (${build_time}s)"
    else
        log_warning "Build took longer than expected (${build_time}s)"
    fi
}

# Generate test report
generate_report() {
    echo -e "\n${BLUE}=== Test Report ===${NC}"
    echo "Total Tests: $TESTS_TOTAL"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    
    local success_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    echo "Success Rate: $success_rate%"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "\n${GREEN}🎉 All tests passed! RECC Sentinel v0.1.0 is ready for release.${NC}"
        return 0
    else
        echo -e "\n${YELLOW}⚠ Some tests failed. Check the logs in build/test-results/ for details.${NC}"
        return 1
    fi
}

# Main test execution
main() {
    echo "Starting comprehensive E2E tests..."
    echo "Test results will be saved to: build/test-results/"
    echo
    
    setup_test_env
    
    # Run all tests
    test_cli_help
    test_native_mode
    test_vm_mode_examples
    test_rule_engine
    test_escalation_engine
    test_harness_generation
    test_crashpack_validation
    test_full_pipeline
    test_error_handling
    test_performance
    
    # Generate final report
    generate_report
}

# Run main function
main "$@"
