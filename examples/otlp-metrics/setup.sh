#!/bin/bash
# examples/otlp-metrics/setup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/otlp_common.sh"

# Without docker there is nothing to set up; exit 0 so run_all.sh does not
# count this as a setup failure — test.sh returns the SKIP code instead
if ! docker_available; then
    print_info "docker not available; skipping setup (test.sh will SKIP)"
    exit 0
fi

check_root
setup_udp_topology
create_mgmt_veth "${NS_TX}" "${MGMT_TX}" "${MGMT_TX_IP}" "${MGMT_TX_HOST}" "${MGMT_TX_HOST_IP}"
create_mgmt_veth "${NS_RX}" "${MGMT_RX}" "${MGMT_RX_IP}" "${MGMT_RX_HOST}" "${MGMT_RX_HOST_IP}"

docker rm -f "${OTEL_CONTAINER}" >/dev/null 2>&1 || true
docker run -d --name "${OTEL_CONTAINER}" --network host \
    -v "${SCRIPT_DIR}/otelcol.yaml:/etc/otelcol/config.yaml:ro" \
    "${OTEL_IMAGE}" >/dev/null

# Wait until both the OTLP gRPC receiver and the prometheus exporter
# (scraped by test.sh) are listening
for i in $(seq 1 100); do
    if ! docker ps -q -f "name=^${OTEL_CONTAINER}$" | grep -q .; then
        print_error "Collector container exited during startup"
        docker logs "${OTEL_CONTAINER}" 2>&1 | tail -n 20 || true
        exit 1
    fi
    if ss -ltn "sport = :${OTLP_PORT}" | grep -q LISTEN \
        && ss -ltn "sport = :${PROM_PORT}" | grep -q LISTEN; then
        print_success "Collector ready: OTLP gRPC :${OTLP_PORT}, prometheus :${PROM_PORT}"
        exit 0
    fi
    sleep 0.1
done
print_error "Collector did not listen on :${OTLP_PORT} and :${PROM_PORT} within 10s"
docker logs "${OTEL_CONTAINER}" 2>&1 | tail -n 20 || true
exit 1
