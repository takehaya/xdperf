#!/bin/bash
# examples/simpleudp-split-rx/common.sh
# Scenario-local parameters (meant to be sourced). This scenario does not use
# the shared two-netns topology from udp_scenario.sh — one xdperf process owns
# both ends and a middle namespace forwards between them — so only the generic
# helpers are pulled in here.

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../common" && pwd)"
source "${COMMON_DIR}/test_utils.sh"
source "${COMMON_DIR}/netns.sh"
source "${COMMON_DIR}/veth.sh"

NS_GEN="${NS_GEN:-xdperf-gen}"
NS_DUT="${NS_DUT:-xdperf-dut}"
GEN_TX="${GEN_TX:-gen-tx}"
GEN_RX="${GEN_RX:-gen-rx}"
DUT_A="${DUT_A:-dut-a}"
DUT_B="${DUT_B:-dut-b}"
GEN_TX_IP="${GEN_TX_IP:-10.0.1.1}"
DUT_A_IP="${DUT_A_IP:-10.0.1.2}"
DUT_B_IP="${DUT_B_IP:-10.0.2.2}"
GEN_RX_IP="${GEN_RX_IP:-10.0.2.1}"

# ~3s run so the per-second stats lines (used by test.sh to verify the RX
# side counted) get several ticks
COUNT="${COUNT:-30k}"
PPS="${PPS:-10k}"
PAYLOAD_SIZE="${PAYLOAD_SIZE:-256}"
DST_PORT="${DST_PORT:-10001}"
PLUGIN="${PLUGIN:-simpleudp.tinygo}"
PASS_THRESHOLD="${PASS_THRESHOLD:-100}"

TX_LOG="${TX_LOG:-${XDPERF_EXAMPLE_RUNDIR}/split-rx.log}"

SKIP_EXIT_CODE=3

# Convert "10k" / "1m" / "10000" to a plain number
to_number() {
    local v="$1"
    case "$v" in
        *k) echo $(( ${v%k} * 1000 )) ;;
        *m) echo $(( ${v%m} * 1000000 )) ;;
        *) echo "$v" ;;
    esac
}
