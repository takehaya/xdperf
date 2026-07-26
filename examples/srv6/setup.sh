#!/bin/bash
# srv6 scenario: build the topology (same v4only veth topology as simpleudp —
# the SRv6 frames are built entirely by the plugin with a static dst MAC, so
# the kernel IPv6 stack stays disabled to keep the XDP counters exact)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

setup_udp_topology
