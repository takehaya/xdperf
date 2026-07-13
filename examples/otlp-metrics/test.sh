#!/bin/bash
# examples/otlp-metrics/test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/otlp_common.sh"

if ! docker_available; then
    print_info "SKIP: docker not available"
    exit "${SKIP_EXIT_CODE}"
fi

rc=0
scenario_preflight || rc=$?
[ "${rc}" -eq 2 ] && exit "${SKIP_EXIT_CODE}"
[ "${rc}" -ne 0 ] && exit 1

if ! docker ps -q -f "name=^${OTEL_CONTAINER}$" | grep -q .; then
    print_error "Collector container not running. Run setup.sh first"
    exit 1
fi

METRICS_DUMP="${XDPERF_EXAMPLE_RUNDIR}/otlp_prom.txt"

# Extract the cumulative xdperf_packets_total for one direction/mode pair
# from the collector's prometheus exporter output
prom_packets() {
    local direction="$1" mode="$2"
    awk -v dir="network_io_direction=\"${direction}\"" \
        -v mode="xdperf_mode=\"${mode}\"" '
        /^xdperf_packets_total\{/ && index($0, dir) && index($0, mode) { v = $2 }
        END { printf "%.0f\n", v + 0 }' "${METRICS_DUMP}"
}

fail_with_logs() {
    print_error "$1"
    print_error "collector log tail:"
    docker logs "${OTEL_CONTAINER}" 2>&1 | tail -n 20 || true
    stop_rx_server
    exit 1
}

# Both sides push over their management link; 1s interval plus the final
# flush on shutdown means even this short run lands in the collector
start_rx_server "${NS_RX}" "${VETH_RX}" "${RX_LOG}" \
    --otlp-endpoint "${MGMT_RX_HOST_IP}:${OTLP_PORT}" --otlp-insecure \
    --otlp-interval 1s --otlp-attributes example.side=rx || exit 1

print_info "Sending: count=${COUNT} pps=${PPS} plugin=${PLUGIN} otlp=${MGMT_TX_HOST_IP}:${OTLP_PORT}"
if ! send_udp \
    --otlp-endpoint "${MGMT_TX_HOST_IP}:${OTLP_PORT}" --otlp-insecure \
    --otlp-interval 1s --otlp-attributes example.side=tx; then
    fail_with_logs "send failed"
fi

sleep 1
# SIGTERM makes the server flush its final cumulative values before exiting
stop_rx_server

expected="$(to_number "${COUNT}")"
required=$(( expected * PASS_THRESHOLD / 100 ))

# Both processes flush their final cumulative values before exiting, but the
# collector may ingest them moments later; retry the scrape briefly (up to
# 10s) instead of failing on the first snapshot
tx_pkts=0
rx_pkts=0
for i in $(seq 1 20); do
    if curl -sf "localhost:${PROM_PORT}/metrics" > "${METRICS_DUMP}"; then
        tx_pkts="$(prom_packets transmit client)"
        rx_pkts="$(prom_packets receive server)"
        if [ "${tx_pkts}" -eq "${expected}" ] && [ "${rx_pkts}" -ge "${required}" ]; then
            break
        fi
    fi
    sleep 0.5
done

print_info "Collector saw: transmit=${tx_pkts} receive=${rx_pkts} (sent ${expected}, threshold ${PASS_THRESHOLD}%)"
if [ "${tx_pkts}" -ne "${expected}" ]; then
    fail_with_logs "FAIL: xdperf_packets_total{transmit,client}=${tx_pkts}, expected exactly ${expected}"
fi
if [ "${rx_pkts}" -lt "${required}" ] || [ "${rx_pkts}" -gt "${expected}" ]; then
    fail_with_logs "FAIL: xdperf_packets_total{receive,server}=${rx_pkts}, expected ${required}..${expected}"
fi

print_success "PASS: OTLP-exported counters match the send count"
print_info "Inspect the pushes with: docker logs ${OTEL_CONTAINER} | grep xdperf"
print_info "Raw prometheus dump: ${METRICS_DUMP}"
exit 0
