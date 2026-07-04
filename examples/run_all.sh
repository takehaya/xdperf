#!/bin/bash
# examples/run_all.sh
# Run every scenario (directories containing test.sh) as setup -> test -> teardown
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common/test_utils.sh"

check_root

SCENARIOS=()
for dir in "${SCRIPT_DIR}"/*/; do
    if [ -f "${dir}test.sh" ]; then
        SCENARIOS+=("$(basename "$dir")")
    fi
done

if [ ${#SCENARIOS[@]} -eq 0 ]; then
    print_error "No scenarios found"
    exit 1
fi

print_info "Found ${#SCENARIOS[@]} scenario(s): ${SCENARIOS[*]}"
echo ""

PASSED=0
FAILED=0
SKIPPED=0
FAILED_SCENARIOS=()

for scenario in "${SCENARIOS[@]}"; do
    echo "========================================"
    print_info "Running scenario: $scenario"
    echo "========================================"

    scenario_dir="${SCRIPT_DIR}/${scenario}"

    if [ -f "${scenario_dir}/setup.sh" ]; then
        if ! "${scenario_dir}/setup.sh"; then
            print_error "Setup failed: $scenario"
            # Clean up a partially built topology so it can't leak into the
            # next scenario
            if [ -f "${scenario_dir}/teardown.sh" ]; then
                "${scenario_dir}/teardown.sh" || true
            fi
            FAILED=$((FAILED + 1))
            FAILED_SCENARIOS+=("$scenario")
            continue
        fi
    fi

    rc=0
    "${scenario_dir}/test.sh" || rc=$?
    if [ "$rc" -eq 0 ]; then
        print_success "Scenario $scenario: PASS"
        PASSED=$((PASSED + 1))
    elif [ "$rc" -eq 3 ]; then
        # SKIP exit code (see examples/common/udp_scenario.sh)
        print_info "Scenario $scenario: SKIP"
        SKIPPED=$((SKIPPED + 1))
    else
        print_error "Scenario $scenario: FAIL"
        FAILED=$((FAILED + 1))
        FAILED_SCENARIOS+=("$scenario")
    fi

    # Always run teardown
    if [ -f "${scenario_dir}/teardown.sh" ]; then
        "${scenario_dir}/teardown.sh" || true
    fi

    echo ""
done

echo "========================================"
echo "Summary"
echo "========================================"
print_info "Total: $((PASSED + FAILED + SKIPPED))"
print_success "Passed: $PASSED"
if [ $SKIPPED -gt 0 ]; then
    print_info "Skipped: $SKIPPED"
fi

if [ $FAILED -gt 0 ]; then
    print_error "Failed: $FAILED"
    print_error "Failed scenarios: ${FAILED_SCENARIOS[*]}"
    exit 1
fi
print_success "All scenarios passed!"
