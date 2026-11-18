#!/bin/bash
# examples/tcp-netkit/common.sh
# Shared definitions and helpers for the tcp-netkit scenario.

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../common" && pwd)"
source "${COMMON_DIR}/test_utils.sh"
source "${COMMON_DIR}/netns.sh"
source "${COMMON_DIR}/veth.sh"

NS_TX="${NS_TX:-xdperf-nk-tx}"
NS_DUT="${NS_DUT:-xdperf-nk-dut}"
NS_RX_L2="${NS_RX_L2:-xdperf-nk-rxl2}"
NS_RX_L3="${NS_RX_L3:-xdperf-nk-rxl3}"

VETH_TX="${VETH_TX:-nk-tx}"
VETH_DUT="${VETH_DUT:-nk-dut-in}"
NK_DUT_L2="${NK_DUT_L2:-nk-dut-l2}"
NK_RX_L2="${NK_RX_L2:-nk-rx-l2}"
NK_DUT_L3="${NK_DUT_L3:-nk-dut-l3}"
NK_RX_L3="${NK_RX_L3:-nk-rx-l3}"

TX_IP4="10.200.1.1"
DUT_IN_IP4="10.200.1.2"
DUT_L2_IP4="10.200.2.1"
RX_L2_IP4="10.200.2.2"
RX_L3_IP4="10.200.3.2"

DST_PORT="${DST_PORT:-5201}"
FLOWS="${FLOWS:-16}"
BYTES="${BYTES:-65536}"
WINDOW="${WINDOW:-16}"
PARALLELISM="${PARALLELISM:-1}"
SKIP_EXIT_CODE=3

SINK_BIN="${SINK_BIN:-${REPO_ROOT}/out/bin/xdperf-sink}"
TCP_PY_DIR="${COMMON_DIR}/py"

PASS_PID_FILE="${XDPERF_EXAMPLE_RUNDIR}/nk-pass.pid"
PASS_LOG="${XDPERF_EXAMPLE_RUNDIR}/nk-pass.log"
SINK_PID_FILE="${XDPERF_EXAMPLE_RUNDIR}/nk-sink.pid"
SINK_LOG="${XDPERF_EXAMPLE_RUNDIR}/nk-sink.log"
AUX_PID_FILE="${XDPERF_EXAMPLE_RUNDIR}/nk-udp-helper.pid"
TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/nk-tx.log"

pid_is() {
    [ -n "$1" ] && [ "$(cat "/proc/$1/comm" 2>/dev/null)" = "$2" ]
}

stop_pidfile() {
    local file="$1" comm="$2" pid
    pid="$(cat "$file" 2>/dev/null)" || return 0
    if pid_is "$pid" "$comm"; then
        kill -INT "$pid" 2>/dev/null || true
        local i
        for i in $(seq 1 50); do
            pid_is "$pid" "$comm" || break
            sleep 0.1
        done
        if pid_is "$pid" "$comm"; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$file"
}

stop_nk_processes() {
    stop_pidfile "${SINK_PID_FILE}" xdperf-sink
    stop_pidfile "${AUX_PID_FILE}" python3
    stop_pidfile "${PASS_PID_FILE}" xdperf-sink
}
