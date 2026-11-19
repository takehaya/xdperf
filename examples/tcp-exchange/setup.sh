#!/bin/bash
# tcp-exchange: build the veth topology.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
setup_tcp_topology
