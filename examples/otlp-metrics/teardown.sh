#!/bin/bash
# examples/otlp-metrics/teardown.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/otlp_common.sh"

check_root

if command -v docker >/dev/null 2>&1; then
    docker rm -f "${OTEL_CONTAINER}" >/dev/null 2>&1 || true
fi

teardown_udp_topology
# Deleting the namespaces removes the mgmt peers too; this covers a
# half-built topology where only the root-netns ends exist
delete_veth_if_ours "${MGMT_TX_HOST}" || true
delete_veth_if_ours "${MGMT_RX_HOST}" || true
print_success "otlp-metrics scenario cleaned up"
