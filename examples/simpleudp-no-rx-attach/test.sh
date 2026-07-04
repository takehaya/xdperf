#!/bin/bash
# simpleudp-no-rx-attach シナリオ: 受信側に XDP を attach しない場合の挙動を実測
#
# veth の XDP 送信経路は peer の NAPI が有効 (= XDP attach または GRO on)
# でないとパケットが silent drop される:
# https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it
#
# Phase 1: XDP attach なし・GRO off → ほぼ届かないことを確認 (drop)
# Phase 2: GRO on → 通常スタックに届くことを確認
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_no_rx_attach_test
