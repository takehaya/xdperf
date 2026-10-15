#!/bin/bash
# tcpstream scenario: build the topology (veth pair + VLAN sub-interfaces)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"

setup_tcp_topology
