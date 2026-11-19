#!/bin/bash
# tcp-exchange: remove the veth topology.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
teardown_tcp_topology
