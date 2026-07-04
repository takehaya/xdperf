#!/bin/bash
# examples/run_all.sh
# 全シナリオ (test.sh を持つディレクトリ) を setup → test → teardown で一括実行
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common/test_utils.sh"

check_root

# シナリオの列挙 (test.sh があるディレクトリ)
SCENARIOS=()
for dir in "${SCRIPT_DIR}"/*/; do
    if [ -f "${dir}test.sh" ]; then
        SCENARIOS+=("$(basename "$dir")")
    fi
done

if [ ${#SCENARIOS[@]} -eq 0 ]; then
    print_error "シナリオが見つかりません"
    exit 1
fi

print_info "${#SCENARIOS[@]} 個のシナリオを実行します: ${SCENARIOS[*]}"
echo ""

PASSED=0
FAILED=0
FAILED_SCENARIOS=()

for scenario in "${SCENARIOS[@]}"; do
    echo "========================================"
    print_info "シナリオ実行: $scenario"
    echo "========================================"

    scenario_dir="${SCRIPT_DIR}/${scenario}"

    # setup
    if [ -f "${scenario_dir}/setup.sh" ]; then
        if ! "${scenario_dir}/setup.sh"; then
            print_error "setup 失敗: $scenario"
            FAILED=$((FAILED + 1))
            FAILED_SCENARIOS+=("$scenario")
            continue
        fi
    fi

    # test
    if "${scenario_dir}/test.sh"; then
        print_success "シナリオ $scenario: PASS"
        PASSED=$((PASSED + 1))
    else
        print_error "シナリオ $scenario: FAIL"
        FAILED=$((FAILED + 1))
        FAILED_SCENARIOS+=("$scenario")
    fi

    # teardown (常に実行)
    if [ -f "${scenario_dir}/teardown.sh" ]; then
        "${scenario_dir}/teardown.sh" || true
    fi

    echo ""
done

echo "========================================"
echo "Summary"
echo "========================================"
print_info "Total: $((PASSED + FAILED))"
print_success "Passed: $PASSED"

if [ $FAILED -gt 0 ]; then
    print_error "Failed: $FAILED"
    print_error "Failed scenarios: ${FAILED_SCENARIOS[*]}"
    exit 1
fi
print_success "All scenarios passed!"
