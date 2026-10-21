#!/bin/bash
# tcp-vxlan: teardown the shared TCP plugin topology.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_plugin_scenario.sh"
teardown_tcp_plugin_topology
