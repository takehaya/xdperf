#!/bin/bash
# simpleudp シナリオ: トポロジ削除
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

teardown_udp_topology
