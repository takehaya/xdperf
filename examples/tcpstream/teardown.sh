#!/bin/bash
# tcpstream scenario: remove the topology
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"

teardown_tcp_topology
