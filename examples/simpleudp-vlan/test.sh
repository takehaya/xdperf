#!/bin/bash
# simpleudp-vlan シナリオ: outer 802.1Q タグ付き UDP を送信し、
# 受信側 XDP (xdp_rx は VLAN タグを剥いてパースする) のカウンタで検証
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# outer 802.1Q タグ (vlan_id != 0 でタグ付与)
export VLAN_ID="${VLAN_ID:-100}"
export VLAN_PCP="${VLAN_PCP:-3}"

source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_udp_test
