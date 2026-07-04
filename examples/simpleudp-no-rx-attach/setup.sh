#!/bin/bash
# simpleudp-no-rx-attach scenario: build the topology
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

setup_udp_topology
