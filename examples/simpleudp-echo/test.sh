#!/bin/bash
# simpleudp-echo シナリオ: 受信側を --swap-resp のエコーサーバにし、
# XDP_TX で送り返されたパケットを送信側でも数える。
#
# veth の XDP_TX は「打ち返される側にも XDP プログラムが attach されて
# いないと silent drop される」という既知の罠の検証を兼ねる:
# https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it
# xdperf は送信時に自デバイスへ xdp_pass_dummy / xdp_rx を attach して
# これを回避している (pkg/xdperf/xdperf.go runTXPacket)。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export ECHO=1

source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_udp_test
