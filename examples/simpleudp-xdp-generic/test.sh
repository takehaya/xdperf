#!/bin/bash
# simpleudp-xdp-generic scenario: force generic (SKB) mode XDP attach with
# --xdp-mode generic on both sides and verify send/receive still works
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export XDP_MODE="${XDP_MODE:-generic}"

source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_udp_test
