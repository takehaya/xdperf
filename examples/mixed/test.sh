#!/bin/bash
# UDP + TCP heavy-hitter E2E with independent receive counters.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_plugin_scenario.sh"
prepare_tcp_plugin_test
for mode in ${MIXED_CASES:-finite duration}; do
for workers in ${MIXED_WORKERS:-1 2}; do
    small_bytes=65536
    large_bytes=262144
    run_args=(--count 100000)
    if [ "$mode" = duration ]; then
        small_bytes=4097
        large_bytes=0
        run_args=(--duration 3s)
    fi
    start_sink "${RX_IP4}:${DST_PORT}"
    udp_log="${XDPERF_EXAMPLE_RUNDIR}/mixed-udp-${mode}-${workers}.json"
    start_tcp_helper "$udp_log" "${TCP_PY_DIR}/udp_echo.py" "$RX_IP4"
    mac="$(ip netns exec "$NS_RX" cat "/sys/class/net/${VETH_RX}/address")"
    report="${XDPERF_EXAMPLE_RUNDIR}/mixed-${mode}-${workers}.csv"
    TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/mixed-${mode}-${workers}.log"
    config="$(python3 "${TCP_PY_DIR}/config.py" mixed "$TX_IP4" "$RX_IP4" "$mac" "$small_bytes" "$large_bytes" "$DST_PORT")"
    run_tcp_plugin "$config" "$report" --recv "${run_args[@]}" --pps 2000 --parallelism "$workers"
    sleep .2
    kill -TERM "$TCP_HELPER_PID"
    wait "$TCP_HELPER_PID"
    rm -f "$AUX_PID_FILE"
    stop_sink
    python3 "${TCP_PY_DIR}/verify.py" mixed "$report" "$SINK_LOG" "$TX_LOG" "$udp_log" "$mode"
    print_success "mixed ${mode} workers=${workers}: TCP completed, UDP TX/RX and ratio verified"
done
done
