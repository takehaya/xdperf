#!/bin/bash
# simpleudp-scx scenario: same UDP flow as simpleudp, but the TX worker CPUs
# are dedicated to xdperf via the sched_ext scheduler (--scx). SKIPs on
# kernels without sched_ext (needs >= 6.13 with CONFIG_SCHED_EXT).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SCX=1
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_udp_test
