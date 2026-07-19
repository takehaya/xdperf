#!/bin/bash
# examples/otlp-metrics/otlp_common.sh
# Shared definitions for the otlp-metrics scenario (meant to be sourced)
#
# Topology: the measurement veth pair from udp_scenario.sh, plus one
# management veth per namespace into the root netns. The receive side
# XDP_DROPs every IPv4/IPv6 frame on the measurement path, so the OTLP
# gRPC push must travel on its own links (see docs/ja/otlp_metrics.md).

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCENARIO_DIR}/../common/udp_scenario.sh"

OTEL_IMAGE="${OTEL_IMAGE:-otel/opentelemetry-collector:0.156.0}"
OTEL_CONTAINER="${OTEL_CONTAINER:-xdperf-otelcol}"
OTLP_PORT="${OTLP_PORT:-4317}"
PROM_PORT="${PROM_PORT:-8889}"

# Management links (netns end / root-netns end)
MGMT_TX="${MGMT_TX:-mgmt-tx}"
MGMT_TX_HOST="${MGMT_TX_HOST:-mgmt-txh}"
MGMT_TX_IP="${MGMT_TX_IP:-192.168.200.1}"
MGMT_TX_HOST_IP="${MGMT_TX_HOST_IP:-192.168.200.2}"
MGMT_RX="${MGMT_RX:-mgmt-rx}"
MGMT_RX_HOST="${MGMT_RX_HOST:-mgmt-rxh}"
MGMT_RX_IP="${MGMT_RX_IP:-192.168.201.1}"
MGMT_RX_HOST_IP="${MGMT_RX_HOST_IP:-192.168.201.2}"

docker_available() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# Create a management veth pair with one end in a namespace and the other
# left in the root netns (create_veth_pair assumes both ends move into a
# namespace, so this is done inline; delete_veth_if_ours guards reuse)
# Usage: create_mgmt_veth <ns> <ns_dev> <ns_ip> <host_dev> <host_ip>
create_mgmt_veth() {
    local ns="$1" ns_dev="$2" ns_ip="$3" host_dev="$4" host_ip="$5"

    delete_veth_if_ours "$ns_dev" || return 1
    delete_veth_if_ours "$host_dev" || return 1
    ip link add "$ns_dev" type veth peer name "$host_dev"
    ip link set "$ns_dev" netns "$ns"
    ip netns exec "$ns" ip link set "$ns_dev" up
    ip link set "$host_dev" up
    ip netns exec "$ns" ip addr add "${ns_ip}/24" dev "$ns_dev"
    ip addr add "${host_ip}/24" dev "$host_dev"

    echo "Created mgmt veth: $ns_dev ($ns, $ns_ip) <-> $host_dev (root, $host_ip)"
}
