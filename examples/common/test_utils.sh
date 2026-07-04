#!/bin/bash
# examples/common/test_utils.sh
# 共通ユーティリティ (source して使う)
#
# 依存: iproute2 (ip), ethtool
# 前提: リポジトリルートで `make build` 済み (out/bin/xdperf と *.wasm)

# 色付き出力
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# root チェック
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "このスクリプトは root で実行してください (sudo)"
        exit 1
    fi
}

# コマンドを表示してから実行 (失敗したら exit)
run() {
    echo "$@"
    "$@" || exit 1
}

# ---- xdperf バイナリ / プラグインのパス解決 --------------------------------
# EXAMPLES_DIR は各スクリプトが source 前に設定する (examples/ のパス)
REPO_ROOT="${REPO_ROOT:-$(cd "${EXAMPLES_DIR}/.." && pwd)}"
XDPERF_BIN="${XDPERF_BIN:-${REPO_ROOT}/out/bin/xdperf}"
PLUGIN_PATH="${PLUGIN_PATH:-${REPO_ROOT}/out/bin}"

check_xdperf_built() {
    if [ ! -x "${XDPERF_BIN}" ]; then
        print_error "xdperf が見つかりません: ${XDPERF_BIN}"
        print_error "リポジトリルートで 'make build' を実行してください"
        exit 1
    fi
}

# ---- xdperf 受信サーバの起動 / 停止 ----------------------------------------
# setsid で親シェルからのシグナル伝播を切る。XDPERF_RX_PID に PID を入れる。
# 第4引数以降は追加フラグ (例: --swap-resp)。
# Usage: start_rx_server <namespace> <device> <log_file> [extra_args...]
start_rx_server() {
    local ns="$1" dev="$2" log="$3"
    shift 3
    # 注意: pkill は -x (プロセス名の完全一致)。-f だとコマンドライン中の
    # "xdperf" にマッチして無関係のプロセスまで殺しかねない (vmlab.sh と同じ配慮)。
    pkill -x xdperf 2>/dev/null || true
    setsid ip netns exec "$ns" "${XDPERF_BIN}" run --device "$dev" --send=false --recv "$@" \
        > "$log" 2>&1 &
    XDPERF_RX_PID=$!
    sleep 2
    if ! kill -0 "${XDPERF_RX_PID}" 2>/dev/null; then
        print_error "受信サーバの起動に失敗しました (log: $log)"
        cat "$log" 2>/dev/null
        return 1
    fi
    print_success "受信サーバ起動 (ns=$ns dev=$dev PID=${XDPERF_RX_PID})"
    return 0
}

# Usage: stop_rx_server
stop_rx_server() {
    pkill -x xdperf 2>/dev/null || true
    sleep 1
}

# ---- 受信カウンタ集計 -------------------------------------------------------
# veth は XDP attach 中 `ethtool -S` に rx_queue_N_xdp_packets を公開する。
# これを合計して返す (標準出力)。
# Usage: rx_xdp_packets <namespace> <device>
rx_xdp_packets() {
    local ns="$1" dev="$2"
    ip netns exec "$ns" ethtool -S "$dev" 2>/dev/null \
        | awk '/rx_queue_[0-9]+_xdp_packets:/ { sum += $2 } END { print sum + 0 }'
}

# ---- 通常スタックの受信カウンタ ----------------------------------------------
# XDP を attach していないデバイスの受信数 (カーネル標準統計)。
# Usage: stack_rx_packets <namespace> <device>
stack_rx_packets() {
    local ns="$1" dev="$2"
    ip netns exec "$ns" cat "/sys/class/net/${dev}/statistics/rx_packets"
}

# ---- live-frames サポート確認 -----------------------------------------------
# 送信側は BPF_PROG_RUN の live frames で TX するため、非対応カーネルでは
# テスト続行不能。probe の live_frame_mode を見て判定する。
# 戻り値: 0 = サポート, 1 = 非サポート
# Usage: check_live_frames <namespace> <device>
check_live_frames() {
    local ns="$1" dev="$2"
    local out
    out="$(ip netns exec "$ns" "${XDPERF_BIN}" probe --device "$dev" --json 2>/dev/null)" || return 1
    echo "$out" | grep -q '"live_frame_mode"[^,}]*true'
}
