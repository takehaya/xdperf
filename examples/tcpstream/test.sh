#!/bin/bash
# tcpstream scenario: stream TCP from XDP (xdperf run --plugin tcpflow.go) into a kernel
# TCP sink (xdperf-sink) and into the XDP responder (xdperf run --tcp-server)
# over IPv4, IPv6, and both again with an 802.1Q tag, then compare what the
# sender saw acknowledged with what the receiver counted. Two more cases
# stream from a kernel TCP client (socat) into the XDP responder.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"

run_tcp_test
