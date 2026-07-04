#!/bin/bash
# simpleudp シナリオ: veth 越しに UDP を送信し、受信側 XDP カウンタで検証
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_udp_test
