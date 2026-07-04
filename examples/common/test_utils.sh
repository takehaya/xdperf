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

# Root-owned working directory for PID and log files. Everything here runs
# as root, and a fixed path under world-writable /tmp would be exposed to
# symlink planting by other users; /run is writable only by root.
XDPERF_EXAMPLE_RUNDIR="${XDPERF_EXAMPLE_RUNDIR:-/run/xdperf-examples}"
if ! mkdir -p -m 0700 "${XDPERF_EXAMPLE_RUNDIR}" 2>/dev/null && [[ $EUID -eq 0 ]]; then
    # Fail fast as root — later PID/log writes would fail confusingly.
    # Non-root sourcing falls through to check_root's clearer message.
    print_error "Cannot create rundir: ${XDPERF_EXAMPLE_RUNDIR}"
    exit 1
fi

# PID file so a later invocation (teardown, next test run) can target the
# server these examples started instead of a blanket pkill (PID reuse makes
# this best-effort, not a guarantee)
RX_PID_FILE="${RX_PID_FILE:-${XDPERF_EXAMPLE_RUNDIR}/rx.pid}"

# Kill a leftover receive server from a previous (possibly crashed) run,
# identified via the PID file. The PID must still point at an xdperf
# process — guards against PID reuse after a stale file.
kill_stale_rx_server() {
    local pid
    pid="$(cat "${RX_PID_FILE}" 2>/dev/null)" || return 0
    if [ -n "$pid" ] && [ "$(cat "/proc/${pid}/comm" 2>/dev/null)" = "xdperf" ]; then
        kill "$pid" 2>/dev/null || true
        # Not our child; poll briefly for exit
        local i
        for i in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
    fi
    rm -f "${RX_PID_FILE}"
}

# Start the xdperf receive server in a namespace and wait until its XDP
# program is attached. setsid isolates it from parent-shell signals; extra
# args (e.g. --swap-resp) are passed through. Sets XDPERF_RX_PID and writes
# the PID file.
# Usage: start_rx_server <namespace> <device> <log_file> [extra_args...]
start_rx_server() {
    local ns="$1" dev="$2" log="$3"
    shift 3
    kill_stale_rx_server
    setsid ip netns exec "$ns" "${XDPERF_BIN}" run --device "$dev" --send=false --recv "$@" \
        > "$log" 2>&1 &
    XDPERF_RX_PID=$!
    echo "${XDPERF_RX_PID}" > "${RX_PID_FILE}"

    local i
    for i in $(seq 1 50); do
        if ! kill -0 "${XDPERF_RX_PID}" 2>/dev/null; then
            print_error "Failed to start receive server (log: $log)"
            cat "$log" 2>/dev/null
            rm -f "${RX_PID_FILE}"
            return 1
        fi
        if ip netns exec "$ns" ip -d link show dev "$dev" 2>/dev/null | grep -q "prog/xdp"; then
            print_success "Receive server started (ns=$ns dev=$dev PID=${XDPERF_RX_PID})"
            return 0
        fi
        sleep 0.1
    done
    print_error "Receive server did not attach XDP within 5s (log: $log)"
    # Don't leak the started process into later scenarios
    kill "${XDPERF_RX_PID}" 2>/dev/null || true
    wait "${XDPERF_RX_PID}" 2>/dev/null || true
    rm -f "${RX_PID_FILE}"
    XDPERF_RX_PID=""
    return 1
}

stop_rx_server() {
    if [ -n "${XDPERF_RX_PID:-}" ] && kill -0 "${XDPERF_RX_PID}" 2>/dev/null; then
        kill "${XDPERF_RX_PID}" 2>/dev/null || true
        wait "${XDPERF_RX_PID}" 2>/dev/null || true
        rm -f "${RX_PID_FILE}"
    else
        # No PID in this shell (e.g. teardown after a failed run):
        # fall back to the PID file, never a blanket pkill
        kill_stale_rx_server
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
# Returns 0 if supported, 1 if the kernel lacks support, 2 if probe itself
# failed (callers must treat 2 as an error, not a SKIP).
# Usage: check_live_frames <namespace> <device>
check_live_frames() {
    local ns="$1" dev="$2"
    local out
    out="$(ip netns exec "$ns" "${XDPERF_BIN}" probe --device "$dev" --json 2>/dev/null)" || return 2
    echo "$out" | grep -q '"live_frame_mode"[^,}]*true' || return 1
}
