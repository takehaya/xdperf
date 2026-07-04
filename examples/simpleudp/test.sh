#!/bin/bash
# simpleudp scenario: send UDP across the veth pair and verify with the
# receiver-side XDP counter
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_udp_test
