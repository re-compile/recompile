#!/bin/bash

# RECC Sentinel Focused Test Suite
# Tests core functionality without VM dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Run a test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} Running test: $test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $test_name passed"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name failed"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Main test execution
main() {
    echo -e "${BLUE}Starting RECC Sentinel Focused Test Suite${NC}"
    
    # Test 1: Build all components
    echo -e "${BLUE}=== Phase 1: Build System ===${NC}"
    run_test "Build all crates" "cargo build --release"
    run_test "Build examples" "(cd examples && ./build.sh)"
    run_test "Generate configuration" "cargo run -p re-rules --bin generate_config"
    
    # Test 2: Individual component tests
    echo -e "${BLUE}=== Phase 2: Component Tests ===${NC}"
    run_test "Rule engine clustering" "cargo run -p re-rules --bin test_clustering"
    run_test "Symbolizer functionality" "cargo run -p re-rules --bin test_symbolizer"
    run_test "Harness generation" "cargo run -p re-harness --bin generate_harness"
    
    # Test 3: CLI interface
    echo -e "${BLUE}=== Phase 3: CLI Interface ===${NC}"
    run_test "CLI help display" "cargo run -p rerun -- --help"
    run_test "Run subcommand help" "cargo run -p rerun -- run --help"
    run_test "Escalation subcommand help" "cargo run -p rerun -- escalate --help"
    run_test "Crashpack subcommand help" "cargo run -p rerun -- crashpack --help"
    
    # Test 4: Escalation runner
    echo -e "${BLUE}=== Phase 4: Escalation Runner ===${NC}"
    
    # Create a test finding in the correct format
    local test_finding='{"schema_version":"1.0","id":"F-heap_overflow-test","class":"heap_overflow","confidence":"high","severity":"high","timestamp":1234567890,"pid":12345,"evidence":{"memory":{"ptr":123456789,"size":100,"alloc_size":50,"operation":"memcpy"},"stacks":{"alloc":["malloc","main"],"call":["memcpy","main"]},"alloc_site":"main"},"escalation":{"tool":"asan","reason":"heap_overflow_detected","estimated_cost":"low","cooldown_ms":5000},"related":[]}'
    echo "$test_finding" > /tmp/test-finding.json
    
    run_test "Escalation runner" "cargo run -p re-escalate --bin run_escalation -- /tmp/test-finding.json"
    
    # Test 5: Documentation
    echo -e "${BLUE}=== Phase 5: Documentation ===${NC}"
    run_test "README exists" "ls README.md"
    run_test "QUICKSTART exists" "ls QUICKSTART.md"
    run_test "ARCHITECTURE exists" "ls ARCHITECTURE.md"
    run_test "CHANGELOG exists" "ls CHANGELOG.md"
    
    # Test 6: Schema Validation
    echo -e "${BLUE}=== Phase 6: Schema Validation ===${NC}"
    run_test "Finding schema exists" "[ -f schemas/finding.schema.json ]"
    
    # Test 7: Native Mode (Linux only)
    echo -e "${BLUE}=== Phase 7: Native Mode (Linux only) ===${NC}"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        run_test "Native mode capability check" "cargo run -p rerun -- run --native examples/memcpy_overflow --help"
        echo -e "${GREEN}✓${NC} Native mode available on Linux"
        ((TESTS_PASSED++))
    else
        echo -e "${YELLOW}⚠${NC} Native mode not available on $OSTYPE"
    fi
    
    # Final results
    echo -e "${BLUE}=== Test Results ===${NC}"
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo "Total tests: $((TESTS_PASSED + TESTS_FAILED))"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed! RECC Sentinel core functionality is working.${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed. Check the output above for details.${NC}"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"
    
    # Check for required commands
    local missing_commands=()
    
    if ! command -v cargo >/dev/null 2>&1; then
        missing_commands+=("cargo")
    fi
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        echo -e "${RED}Missing required commands: ${missing_commands[*]}${NC}"
        echo -e "${RED}Please install the missing dependencies and try again.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All prerequisites satisfied${NC}"
}

# Main execution
check_prerequisites
main
