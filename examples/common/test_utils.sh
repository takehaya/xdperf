#!/bin/bash
# examples/common/test_utils.sh
# Shared utilities (meant to be sourced)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (sudo)"
        exit 1
    fi
}

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
XDPERF_BIN="${XDPERF_BIN:-${REPO_ROOT}/out/bin/xdperf}"
PLUGIN_PATH="${PLUGIN_PATH:-${REPO_ROOT}/out/bin}"

check_xdperf_built() {
    if [ ! -x "${XDPERF_BIN}" ]; then
        print_error "xdperf not found: ${XDPERF_BIN} (run 'make build' at the repo root)"
        exit 1
    fi
}

# Start the xdperf receive server in a namespace and wait until its XDP
# program is attached. setsid isolates it from parent-shell signals; extra
# args (e.g. --swap-resp) are passed through. pkill uses -x (exact process
# name) — -f would match "xdperf" in unrelated command lines (same caveat as
# vmlab.sh). Sets XDPERF_RX_PID.
# Usage: start_rx_server <namespace> <device> <log_file> [extra_args...]
start_rx_server() {
    local ns="$1" dev="$2" log="$3"
    shift 3
    pkill -x xdperf 2>/dev/null || true
    setsid ip netns exec "$ns" "${XDPERF_BIN}" run --device "$dev" --send=false --recv "$@" \
        > "$log" 2>&1 &
    XDPERF_RX_PID=$!

    local i
    for i in $(seq 1 50); do
        if ! kill -0 "${XDPERF_RX_PID}" 2>/dev/null; then
            print_error "Failed to start receive server (log: $log)"
            cat "$log" 2>/dev/null
            return 1
        fi
        if ip netns exec "$ns" ip -d link show dev "$dev" 2>/dev/null | grep -q "prog/xdp"; then
            print_success "Receive server started (ns=$ns dev=$dev PID=${XDPERF_RX_PID})"
            return 0
        fi
        sleep 0.1
    done
    print_error "Receive server did not attach XDP within 5s (log: $log)"
    return 1
}

stop_rx_server() {
    if [ -n "${XDPERF_RX_PID:-}" ] && kill -0 "${XDPERF_RX_PID}" 2>/dev/null; then
        kill "${XDPERF_RX_PID}" 2>/dev/null || true
        wait "${XDPERF_RX_PID}" 2>/dev/null || true
    else
        # No PID in this shell (e.g. teardown after a failed run)
        pkill -x xdperf 2>/dev/null || true
        sleep 1
    fi
    XDPERF_RX_PID=""
}

# Sum of the device's rx_queue_N_xdp_packets (exposed by veth while XDP is attached)
# Usage: rx_xdp_packets <namespace> <device>
rx_xdp_packets() {
    local ns="$1" dev="$2"
    ip netns exec "$ns" ethtool -S "$dev" 2>/dev/null \
        | awk '/rx_queue_[0-9]+_xdp_packets:/ { sum += $2 } END { print sum + 0 }'
}

# Kernel-stack receive counter (for devices without XDP attached)
# Usage: stack_rx_packets <namespace> <device>
stack_rx_packets() {
    local ns="$1" dev="$2"
    ip netns exec "$ns" cat "/sys/class/net/${dev}/statistics/rx_packets"
}

# The sender transmits via BPF_PROG_RUN live frames; probe reports support.
# Returns 0 if supported.
# Usage: check_live_frames <namespace> <device>
check_live_frames() {
    local ns="$1" dev="$2"
    local out
    out="$(ip netns exec "$ns" "${XDPERF_BIN}" probe --device "$dev" --json 2>/dev/null)" || return 1
    echo "$out" | grep -q '"live_frame_mode"[^,}]*true'
}
