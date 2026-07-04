#!/bin/bash
# simpleudp-vlan scenario: remove the topology
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

teardown_udp_topology
