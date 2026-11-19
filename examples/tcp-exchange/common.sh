#!/bin/bash
# tcp-exchange: shared settings (meant to be sourced). The topology is the
# tcpstream one under its own namespace and veth names.
export NS_TX="xdperf-xchg-tx" NS_RX="xdperf-xchg-rx"
export VETH_TX="xchg-tx" VETH_RX="xchg-rx"
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"
SINK_PID_FILE="${XDPERF_EXAMPLE_RUNDIR}/xchg-sink.pid"
