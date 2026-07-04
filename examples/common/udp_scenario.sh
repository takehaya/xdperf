#!/bin/bash
# examples/common/udp_scenario.sh
# simpleudp 系シナリオの共通実装 (source して使う)
#
# トポロジ:
#   ns: xdperf-tx                     ns: xdperf-rx
#   +----------------+   veth pair   +----------------+
#   | xdp-tx         |===============| xdp-rx         |
#   | 192.168.100.1  |               | 192.168.100.2  |
#   | (live-frames TX)|              | (xdp_rx attach) |
#   +----------------+               +----------------+
#
# 送信側は XDP live-frames (BPF_PROG_RUN) で veth から TX し、受信側は
# xdp_rx プログラムで IPv4/IPv6 フレームを数える。veth の ndo_xdp_xmit は
# peer に XDP プログラムが attach されている必要があるため、受信サーバを
# 先に起動してから送信する。
#
# 環境変数で上書き可:
#   COUNT (10k) / PPS (10k) / PAYLOAD_SIZE (256) / DST_PORT (10001)
#   PLUGIN (simpleudp.tinygo) / VLAN_ID (0=タグなし) / VLAN_PCP (0)
#   PASS_THRESHOLD (100 = 受信数が送信数の100%で PASS)

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="${EXAMPLES_DIR:-$(cd "${COMMON_DIR}/.." && pwd)}"

source "${COMMON_DIR}/test_utils.sh"
source "${COMMON_DIR}/netns.sh"
source "${COMMON_DIR}/veth.sh"

# ---- トポロジ定義 -----------------------------------------------------------
NS_TX="${NS_TX:-xdperf-tx}"
NS_RX="${NS_RX:-xdperf-rx}"
VETH_TX="${VETH_TX:-xdp-tx}"
VETH_RX="${VETH_RX:-xdp-rx}"
TX_IP="${TX_IP:-192.168.100.1}"
RX_IP="${RX_IP:-192.168.100.2}"

# ---- テストパラメータ ---------------------------------------------------------
COUNT="${COUNT:-10k}"
PPS="${PPS:-10k}"
PAYLOAD_SIZE="${PAYLOAD_SIZE:-256}"
DST_PORT="${DST_PORT:-10001}"
PLUGIN="${PLUGIN:-simpleudp.tinygo}"
VLAN_ID="${VLAN_ID:-0}"
VLAN_PCP="${VLAN_PCP:-0}"
PASS_THRESHOLD="${PASS_THRESHOLD:-100}"

RX_LOG="${RX_LOG:-/tmp/xdperf-example-rx.log}"
TX_LOG="${TX_LOG:-/tmp/xdperf-example-tx.log}"

# "10k" / "1m" / "10000" を数値へ
to_number() {
    local v="$1"
    case "$v" in
        *k) echo $(( ${v%k} * 1000 )) ;;
        *m) echo $(( ${v%m} * 1000000 )) ;;
        *) echo "$v" ;;
    esac
}

# ---- setup / teardown --------------------------------------------------------
setup_udp_topology() {
    check_root
    create_netns "${NS_TX}"
    create_netns "${NS_RX}"
    create_veth_pair "${VETH_TX}" "${NS_TX}" "${VETH_RX}" "${NS_RX}"
    configure_veth_v4only "${NS_TX}" "${VETH_TX}" "${TX_IP}/24"
    configure_veth_v4only "${NS_RX}" "${VETH_RX}" "${RX_IP}/24"
    print_success "トポロジ構築完了: ${NS_TX}(${VETH_TX}) <-> ${NS_RX}(${VETH_RX})"
}

teardown_udp_topology() {
    check_root
    stop_rx_server
    delete_netns "${NS_TX}"
    delete_netns "${NS_RX}"
    print_success "トポロジ削除完了"
}

# ---- テスト本体 ---------------------------------------------------------------
run_udp_test() {
    check_root
    check_xdperf_built

    if ! ip netns pids "${NS_TX}" >/dev/null 2>&1 || ! ip netns pids "${NS_RX}" >/dev/null 2>&1; then
        print_error "netns がありません。先に setup.sh を実行してください"
        return 1
    fi

    # live-frames 非対応カーネルでは送信不能なので SKIP (CI フェイルセーフ)
    if ! check_live_frames "${NS_TX}" "${VETH_TX}"; then
        print_info "このカーネルは XDP live-frames (BPF_PROG_RUN) 非対応のため SKIP します"
        return 0
    fi

    # 受信サーバを先に起動 (veth の XDP TX 経路は peer への XDP attach が前提)
    start_rx_server "${NS_RX}" "${VETH_RX}" "${RX_LOG}" || return 1

    # ベースライン (veth カウンタは累積なので前回実行分を差し引く)
    local base after delta expected
    base="$(rx_xdp_packets "${NS_RX}" "${VETH_RX}")"

    # 送信設定。vlan_id != 0 なら outer 802.1Q タグを付ける
    local cfg="{\"src_ip\":\"${TX_IP}\",\"dst_ip\":\"${RX_IP}\",\"dst_port\":${DST_PORT},\"payload_size\":${PAYLOAD_SIZE},\"is_arp_resolve\":false"
    if [ "${VLAN_ID}" -ne 0 ]; then
        cfg+=",\"vlan_id\":${VLAN_ID},\"vlan_pcp\":${VLAN_PCP}"
    fi
    cfg+="}"

    print_info "送信開始: count=${COUNT} pps=${PPS} plugin=${PLUGIN} cfg=${cfg}"
    if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --device "${VETH_TX}" \
        --plugin "${PLUGIN}" --plugin-path "${PLUGIN_PATH}" \
        --count "${COUNT}" --pps "${PPS}" \
        --cfg "${cfg}" > "${TX_LOG}" 2>&1; then
        print_error "送信に失敗しました (log: ${TX_LOG})"
        tail -n 20 "${TX_LOG}"
        stop_rx_server
        return 1
    fi

    # 送信完了後の反映待ち → 集計
    sleep 1
    after="$(rx_xdp_packets "${NS_RX}" "${VETH_RX}")"
    stop_rx_server

    delta=$(( after - base ))
    expected="$(to_number "${COUNT}")"
    local required=$(( expected * PASS_THRESHOLD / 100 ))

    print_info "送信 ${expected} packets / 受信 ${delta} packets (threshold: ${PASS_THRESHOLD}%)"
    if [ "${delta}" -ge "${required}" ] && [ "${delta}" -le "${expected}" ]; then
        print_success "PASS: 受信カウンタが期待値と一致"
        return 0
    fi
    print_error "FAIL: 受信 ${delta} / 期待 ${expected} (最低 ${required})"
    print_error "rx ログ末尾:"
    tail -n 10 "${RX_LOG}" 2>/dev/null || true
    return 1
}
