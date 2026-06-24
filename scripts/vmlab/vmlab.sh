#!/usr/bin/env bash
#
# vmlab.sh — XDPerf VM-to-VM テストラボ（自己完結 QEMU 版）
#
# 2 つの VM (tx / rx) を QEMU の socket netdev で back-to-back 直結し、
# 片方で送信・片方で受信して end-to-end の実カウンタを取れる再現環境を作る。
#
#   - 管理 NIC : user-mode netdev + hostfwd で ssh 制御
#   - データ NIC: virtio-net を socket netdev で 2VM 直結（試験対象の経路）
#   - xdperf   : host でビルドした out/ を 9p/virtfs で read-only マウントして投入
#
# 使い方:
#   scripts/vmlab/vmlab.sh image     # ベースクラウドイメージを取得（初回のみ）
#   scripts/vmlab/vmlab.sh up        # 2VM 起動（ssh 疎通まで待つ）
#   scripts/vmlab/vmlab.sh status    # 稼働状況 / ssh ポート表示
#   scripts/vmlab/vmlab.sh ssh tx    # tx VM に入る（rx も可）
#   scripts/vmlab/vmlab.sh demo      # rx で受信・tx で送信し、両側の実カウンタを表示
#   scripts/vmlab/vmlab.sh down      # 2VM 停止
#   scripts/vmlab/vmlab.sh clean     # overlay/seed/log を削除（ベースイメージは残す）
#
# 注意:
#   - QEMU socket リンクは host のユーザ空間処理が律速。end-to-end の到達 pps は
#     送信側の生成レートより大幅に低い。本ラボは「機能・正当性の end-to-end 検証」と
#     「再現環境」が目的。スループットのヘッドラインは送信側 NIC カウンタ(xdp_tx)で取ること。
#   - データ NIC は単一キュー（socket netdev の制約）。データ経路の parallelism は 1 想定。
#
set -euo pipefail

# ---- パス解決 -------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CI_DIR="${SCRIPT_DIR}/cloud-init"
CACHE_DIR="${REPO_ROOT}/.cache/vmlab"
SHARE_DIR="${REPO_ROOT}/out"   # 9p で VM に渡すディレクトリ（make build の成果物）

# ---- 設定（環境変数で上書き可） ------------------------------------------
BASE_IMAGE_URL="${VMLAB_BASE_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
BASE_IMAGE="${CACHE_DIR}/base.qcow2"
VM_MEM="${VMLAB_MEM:-4G}"
VM_CPUS="${VMLAB_CPUS:-4}"
DISK_SIZE="${VMLAB_DISK:-20G}"
DATA_PORT="${VMLAB_DATA_PORT:-12345}"      # データ NIC 直結用の host TCP ポート
SSH_PORT_TX="${VMLAB_SSH_PORT_TX:-2222}"
SSH_PORT_RX="${VMLAB_SSH_PORT_RX:-2223}"
SSH_KEY="${CACHE_DIR}/id_vmlab"
GUEST_USER="${VMLAB_GUEST_USER:-ubuntu}"
RUN_USER="${USER:-$(id -un)}"   # set -u 下で $USER 未定義(cron/CI)でも動くようフォールバック

# データ経路の設定（cloud-init の network-config と揃える）
DATA_IF="data"                 # set-name で固定する guest 内 NIC 名
TX_DATA_IP="192.168.1.1"
RX_DATA_IP="192.168.1.2"
DEMO_PARALLELISM="${VMLAB_PARALLELISM:-1}"
DEMO_PAYLOAD="${VMLAB_PAYLOAD:-1200}"
DEMO_COUNT="${VMLAB_COUNT:-10k}"
DEMO_SECONDS="${VMLAB_DEMO_SECONDS:-8}"
PLUGIN="${VMLAB_PLUGIN:-simpleudp.tinygo}"

# データリンク方式: socket (自己完結・単一キュー) | tap (host bridge+tap・vhost・マルチキュー)
# up 実行時の方式を .cache に記録し、demo/down が自動追従する（env 指定があれば優先）。
DATA_LINK="${VMLAB_DATA_LINK:-$(cat "${CACHE_DIR}/datalink" 2>/dev/null || echo socket)}"
DATA_QUEUES="${VMLAB_DATA_QUEUES:-$(cat "${CACHE_DIR}/dataqueues" 2>/dev/null || echo "${VM_CPUS}")}"
# NIC リング(descriptor)サイズ。qemu virtio-net の rx/tx_queue_size と guest ethtool -G を揃える。
# 256〜1024 の 2 の冪。256 が virtio 既定（それ以上は qemu 側で上限を引き上げる必要がある）。
QUEUE_SIZE="${VMLAB_QUEUE_SIZE:-$(cat "${CACHE_DIR}/queuesize" 2>/dev/null || echo 256)}"
BRIDGE="${VMLAB_BRIDGE:-xdpbr0}"
TAP_TX="${VMLAB_TAP_TX:-xdptaptx}"
TAP_RX="${VMLAB_TAP_RX:-xdptaprx}"

# vhostuser (OVS-DPDK) モード用
OVS_BRIDGE="${VMLAB_OVS_BRIDGE:-xdpovs0}"
PMD_CPU_MASK="${VMLAB_PMD_CPU_MASK:-0x3c}"   # OVS-DPDK PMD コアマスク (0x3c = core 2-5)
VHOST_SOCK_TX="${CACHE_DIR}/vhost-tx.sock"   # QEMU(server)が作る vhost-user ソケット (user所有)
VHOST_SOCK_RX="${CACHE_DIR}/vhost-rx.sock"
HUGE_DIR="${VMLAB_HUGE_DIR:-/dev/hugepages/xdperf}"  # QEMU が hugepage を使う user 所有サブディレクトリ
# hugepage 不足時に drop_caches + compaction + 自動確保（ホスト全体に影響する破壊的操作）を行うか。
# 既定は無効。不足時は警告して停止する。明示的に許可する場合のみ 1 にする。
HUGEPAGES_FORCE="${VMLAB_HUGEPAGES_FORCE:-0}"

# 固定 MAC（network-config の match と一致させる）
MAC_TX_MGMT="52:54:00:00:00:11"
MAC_TX_DATA="52:54:00:11:11:11"
MAC_RX_MGMT="52:54:00:00:00:22"
MAC_RX_DATA="52:54:00:22:22:22"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)

# ---- ユーティリティ -------------------------------------------------------
log()  { printf '\033[1;34m[vmlab]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[vmlab]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[vmlab]\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "必要なコマンドが見つかりません: $1"; }

check_tools() {
  need qemu-system-x86_64
  need qemu-img
  need genisoimage
  need curl
  need ssh
  need ssh-keygen
  if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    warn "/dev/kvm にアクセスできません。'sudo chmod 0666 /dev/kvm' か kvm グループ参加が必要かもしれません。"
  fi
}

ssh_port_for() { [[ "$1" == "tx" ]] && echo "${SSH_PORT_TX}" || echo "${SSH_PORT_RX}"; }
mgmt_mac_for() { [[ "$1" == "tx" ]] && echo "${MAC_TX_MGMT}" || echo "${MAC_RX_MGMT}"; }
data_mac_for() { [[ "$1" == "tx" ]] && echo "${MAC_TX_DATA}" || echo "${MAC_RX_DATA}"; }
data_ip_for()  { [[ "$1" == "tx" ]] && echo "${TX_DATA_IP}"  || echo "${RX_DATA_IP}"; }

# virtio-net + vhost-net では tx_queue_size の上限が 256（rx は 1024 まで可）。
# QUEUE_SIZE が 256 超でも tx は 256 にクランプする。
tx_ring_size() { [[ "${QUEUE_SIZE}" -gt 256 ]] && echo 256 || echo "${QUEUE_SIZE}"; }

vm_ssh() {
  local role="$1"; shift
  local port; port="$(ssh_port_for "${role}")"
  ssh "${SSH_OPTS[@]}" -i "${SSH_KEY}" -p "${port}" "${GUEST_USER}@127.0.0.1" "$@"
}

# ---- tap+bridge データリンク（マルチキュー / vhost） ----------------------
tap_name_for() { [[ "$1" == "tx" ]] && echo "${TAP_TX}" || echo "${TAP_RX}"; }

# host 側に bridge と multi_queue tap を作る（sudo 必要。qemu は非特権で開けるよう user 所有にする）
setup_tap_link() {
  need ip
  command -v modprobe >/dev/null && sudo modprobe vhost_net 2>/dev/null || true
  if ! ip link show "${BRIDGE}" >/dev/null 2>&1; then
    log "host bridge 作成: ${BRIDGE}"
    sudo ip link add "${BRIDGE}" type bridge
    sudo ip link set "${BRIDGE}" up
    touch "${CACHE_DIR}/bridge-created"   # 自分で作った印。既存の同名 bridge は teardown で消さない
  fi
  local role tap
  for role in tx rx; do
    tap="$(tap_name_for "${role}")"
    if ! ip link show "${tap}" >/dev/null 2>&1; then
      log "host tap 作成: ${tap} (multi_queue, owner=${RUN_USER})"
      sudo ip tuntap add dev "${tap}" mode tap multi_queue user "${RUN_USER}"
      sudo ip link set "${tap}" master "${BRIDGE}"
      sudo ip link set "${tap}" up
    fi
  done
}

teardown_tap_link() {
  local role tap
  for role in tx rx; do
    tap="$(tap_name_for "${role}")"
    if ip link show "${tap}" >/dev/null 2>&1; then
      log "host tap 削除: ${tap}"
      sudo ip link del "${tap}" 2>/dev/null || true
    fi
  done
  # bridge は自分で作った場合のみ削除する（既存の同名 bridge を破壊しない）
  if [[ -f "${CACHE_DIR}/bridge-created" ]]; then
    if ip link show "${BRIDGE}" >/dev/null 2>&1; then
      log "host bridge 削除: ${BRIDGE}"
      sudo ip link del "${BRIDGE}" 2>/dev/null || true
    fi
    rm -f "${CACHE_DIR}/bridge-created"
  fi
}

# ---- vhostuser (OVS-DPDK) データリンク（ユーザ空間PMDポーリング） ----------
vhost_sock_for() { [[ "$1" == "tx" ]] && echo "${VHOST_SOCK_TX}" || echo "${VHOST_SOCK_RX}"; }

# OVS-DPDK の netdev ブリッジ + dpdkvhostuserclient ポート2つを作る。
# QEMU が vhost-user の server（ソケットは user 所有）、OVS が client で接続する。
setup_vhostuser_link() {
  need ovs-vsctl
  need ovs-ofctl
  [[ "$(sudo ovs-vsctl get Open_vSwitch . dpdk_initialized 2>/dev/null)" == "true" ]] \
    || die "OVS-DPDK が初期化されていません (other_config:dpdk-init=true + ovs-vswitchd 再起動が必要)"

  # ゲストメモリは共有 hugepage に載せる必要がある。2VM分 + OVS mempool/slack を確保。
  # 長期稼働ホストは断片化で runtime 確保が失敗するので drop_caches + compaction してから割当。
  local mem_gb pages_needed got nr
  [[ "${VM_MEM}" =~ ^[0-9]+[Gg]$ ]] \
    || die "vhostuser モードでは VMLAB_MEM を G 単位で指定してください（例: 4G）。現在: ${VM_MEM}"
  mem_gb="${VM_MEM%[Gg]}"
  pages_needed=$(( mem_gb * 512 * 2 + 2048 ))   # 2MB ページ数
  nr="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
  if [[ "${nr}" -lt "${pages_needed}" ]]; then
    [[ "${HUGEPAGES_FORCE}" == "1" ]] \
      || die "hugepages が不足しています (現在 ${nr}, 必要 ${pages_needed})。事前に確保するか、ホスト全体に影響する drop_caches+自動確保を許可する場合のみ VMLAB_HUGEPAGES_FORCE=1 を指定してください。"
    log "hugepages 確保(FORCE): drop_caches + compaction -> ${pages_needed} (2MB pages)"
    sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches; echo 1 > /proc/sys/vm/compact_memory'
    sudo sh -c "echo ${pages_needed} > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
  fi
  got="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
  log "hugepages nr=${got} free=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages) (2VM必要≈$(( mem_gb * 512 * 2 )))"
  [[ "${got}" -ge "$(( mem_gb * 512 * 2 ))" ]] \
    || warn "hugepages が要求量に届きません (nr=${got})。VMLAB_MEM を下げてください。"

  # QEMU(非特権) が hugepage を使えるよう user 所有のサブディレクトリを用意
  sudo mkdir -p "${HUGE_DIR}"
  sudo chown "${RUN_USER}" "${HUGE_DIR}"

  log "OVS PMD cpu mask=${PMD_CPU_MASK}"
  # 既存の pmd-cpu-mask を退避し（teardown で復元）、既存 OVS-DPDK 設定を壊さない。未設定なら空ファイル。
  sudo ovs-vsctl get Open_vSwitch . other_config:pmd-cpu-mask 2>/dev/null \
    | tr -d '"' > "${CACHE_DIR}/pmd-cpu-mask.prev" || true
  sudo ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask="${PMD_CPU_MASK}"

  log "OVS bridge 作成: ${OVS_BRIDGE} (datapath_type=netdev) + dpdkvhostuserclient x2"
  sudo ovs-vsctl --may-exist add-br "${OVS_BRIDGE}" -- set bridge "${OVS_BRIDGE}" datapath_type=netdev
  sudo ovs-vsctl --may-exist add-port "${OVS_BRIDGE}" vhu-tx \
    -- set Interface vhu-tx type=dpdkvhostuserclient options:vhost-server-path="${VHOST_SOCK_TX}"
  sudo ovs-vsctl --may-exist add-port "${OVS_BRIDGE}" vhu-rx \
    -- set Interface vhu-rx type=dpdkvhostuserclient options:vhost-server-path="${VHOST_SOCK_RX}"
  sudo ovs-ofctl del-flows "${OVS_BRIDGE}"   # 再実行時に同一フローを重複させない
  sudo ovs-ofctl add-flow "${OVS_BRIDGE}" actions=NORMAL
}

teardown_vhostuser_link() {
  command -v ovs-vsctl >/dev/null || return 0
  if sudo ovs-vsctl br-exists "${OVS_BRIDGE}" 2>/dev/null; then
    log "OVS bridge 削除: ${OVS_BRIDGE}"
    sudo ovs-vsctl --if-exists del-br "${OVS_BRIDGE}"
  fi
  # pmd-cpu-mask は退避値があれば復元、無ければ（元々未設定なら）remove する
  if [[ -s "${CACHE_DIR}/pmd-cpu-mask.prev" ]]; then
    sudo ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask="$(cat "${CACHE_DIR}/pmd-cpu-mask.prev")"
  else
    sudo ovs-vsctl remove Open_vSwitch . other_config pmd-cpu-mask 2>/dev/null || true
  fi
  rm -f "${CACHE_DIR}/pmd-cpu-mask.prev"
  rm -f "${VHOST_SOCK_TX}" "${VHOST_SOCK_RX}"
  [[ "${HUGE_DIR}" == /dev/hugepages/* ]] && sudo rm -rf "${HUGE_DIR}" 2>/dev/null || true
}

# role に応じた qemu のデータ NIC 引数を配列で標準出力に出す
data_netdev_args() {
  local role="$1" data_mac="$2"
  local ring=",rx_queue_size=${QUEUE_SIZE},tx_queue_size=$(tx_ring_size)"
  local vectors=$(( DATA_QUEUES * 2 + 2 ))
  case "${DATA_LINK}" in
    tap)
      local tap; tap="$(tap_name_for "${role}")"
      printf '%s\n' \
        "-netdev" "tap,id=data,ifname=${tap},script=no,downscript=no,vhost=on,queues=${DATA_QUEUES}" \
        "-device" "virtio-net-pci,netdev=data,mac=${data_mac},mq=on,vectors=${vectors}${ring}" ;;
    vhostuser)
      local sock; sock="$(vhost_sock_for "${role}")"
      # QEMU が vhost-user の server（OVS が client で接続）。共有hugepageメモリが前提。
      printf '%s\n' \
        "-chardev" "socket,id=chardata,path=${sock},server=on,wait=off" \
        "-netdev" "vhost-user,id=data,chardev=chardata,queues=${DATA_QUEUES}" \
        "-device" "virtio-net-pci,netdev=data,mac=${data_mac},mq=on,vectors=${vectors}${ring}" ;;
    *)
      # socket back-to-back（単一キュー）。tx を listener、rx を connector にする。
      local spec="socket,id=data,connect=127.0.0.1:${DATA_PORT}"
      [[ "${role}" == "tx" ]] && spec="socket,id=data,listen=127.0.0.1:${DATA_PORT}"
      printf '%s\n' "-netdev" "${spec}" "-device" "virtio-net-pci,netdev=data,mac=${data_mac}${ring}" ;;
  esac
}

# ---- イメージ取得 ---------------------------------------------------------
cmd_image() {
  check_tools
  mkdir -p "${CACHE_DIR}"
  if [[ -f "${BASE_IMAGE}" ]]; then
    log "ベースイメージは既に存在: ${BASE_IMAGE}"
    return
  fi
  log "ベースクラウドイメージを取得: ${BASE_IMAGE_URL}"
  curl -fL --progress-bar -o "${BASE_IMAGE}.tmp" "${BASE_IMAGE_URL}"
  mv "${BASE_IMAGE}.tmp" "${BASE_IMAGE}"
  log "取得完了: ${BASE_IMAGE}"
}

ensure_ssh_key() {
  if [[ ! -f "${SSH_KEY}" ]]; then
    log "ラボ用 SSH 鍵を生成: ${SSH_KEY}"
    ssh-keygen -t ed25519 -N "" -f "${SSH_KEY}" -C "xdperf-vmlab" >/dev/null
  fi
}

# ---- seed ISO 生成（cloud-init NoCloud） ---------------------------------
build_seed() {
  local role="$1"
  local pubkey; pubkey="$(cat "${SSH_KEY}.pub")"
  local work; work="$(mktemp -d)"

  # 共通テンプレートに鍵 / role 別 MAC / IP を差し込む（network-config と MAC を二重管理しない）
  sed "s|__SSH_PUBKEY__|${pubkey}|" "${CI_DIR}/user-data" > "${work}/user-data"
  sed -e "s|__MGMT_MAC__|$(mgmt_mac_for "${role}")|" \
      -e "s|__DATA_MAC__|$(data_mac_for "${role}")|" \
      -e "s|__DATA_IP__|$(data_ip_for "${role}")|" \
      "${CI_DIR}/network-config" > "${work}/network-config"
  cat > "${work}/meta-data" <<EOF
instance-id: xdperf-${role}
local-hostname: ${role}
EOF

  genisoimage -quiet -output "${CACHE_DIR}/${role}-seed.iso" \
    -volid cidata -joliet -rock \
    "${work}/user-data" "${work}/meta-data" "${work}/network-config"
  rm -rf "${work}"
}

build_overlay() {
  local role="$1"
  local overlay="${CACHE_DIR}/${role}-overlay.qcow2"
  [[ -f "${overlay}" ]] && return
  qemu-img create -q -f qcow2 -F qcow2 -b "${BASE_IMAGE}" "${overlay}" "${DISK_SIZE}" >/dev/null
}

# ---- VM 起動 --------------------------------------------------------------
start_vm() {
  local role="$1"
  local ssh_port mgmt_mac data_mac
  ssh_port="$(ssh_port_for "${role}")"
  mgmt_mac="$(mgmt_mac_for "${role}")"
  data_mac="$(data_mac_for "${role}")"

  # データ NIC 引数（socket / tap / vhostuser）を配列で受け取る
  local data_args=()
  mapfile -t data_args < <(data_netdev_args "${role}" "${data_mac}")

  # メモリ引数: vhostuser は共有hugepageバックエンドが必須
  local mem_args=(-m "${VM_MEM}")
  if [[ "${DATA_LINK}" == "vhostuser" ]]; then
    mem_args+=(-object "memory-backend-file,id=mem,size=${VM_MEM},mem-path=${HUGE_DIR},share=on,prealloc=on"
               -numa "node,memdev=mem")
  fi

  build_overlay "${role}"
  build_seed "${role}"

  log "VM 起動: ${role} (ssh: 127.0.0.1:${ssh_port}, data-link: ${DATA_LINK})"
  qemu-system-x86_64 \
    -name "xdperf-${role}" \
    -machine q35,accel=kvm -cpu host -smp "${VM_CPUS}" "${mem_args[@]}" \
    -display none -daemonize \
    -pidfile "${CACHE_DIR}/${role}.pid" \
    -serial "file:${CACHE_DIR}/${role}-serial.log" \
    -drive "file=${CACHE_DIR}/${role}-overlay.qcow2,if=virtio,format=qcow2" \
    -drive "file=${CACHE_DIR}/${role}-seed.iso,if=virtio,format=raw" \
    -netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:${ssh_port}-:22" \
    -device "virtio-net-pci,netdev=mgmt,mac=${mgmt_mac}" \
    "${data_args[@]}" \
    -virtfs "local,path=${SHARE_DIR},mount_tag=xdperfout,security_model=none,readonly=on"
}

wait_ssh() {
  local role="$1"
  log "${role} の ssh / cloud-init 完了待ち..."
  for _ in $(seq 1 60); do
    if vm_ssh "${role}" "cloud-init status --wait >/dev/null 2>&1; test -x /mnt/xdperf/bin/xdperf" 2>/dev/null; then
      log "${role} 準備完了"
      return 0
    fi
    sleep 5
  done
  die "${role} の ssh / セットアップがタイムアウトしました（serial ログ: ${CACHE_DIR}/${role}-serial.log）"
}

cmd_up() {
  check_tools
  ensure_ssh_key
  [[ -f "${BASE_IMAGE}" ]] || die "ベースイメージがありません。先に 'vmlab.sh image' を実行してください。"
  [[ -x "${SHARE_DIR}/bin/xdperf" ]] || die "${SHARE_DIR}/bin/xdperf がありません。先に 'make build' を実行してください。"
  mkdir -p "${CACHE_DIR}"

  # 使用するデータリンク方式 / キュー数 / リングサイズを記録し、demo/down が自動追従できるようにする
  echo "${DATA_LINK}"   > "${CACHE_DIR}/datalink"
  echo "${DATA_QUEUES}" > "${CACHE_DIR}/dataqueues"
  echo "${QUEUE_SIZE}"  > "${CACHE_DIR}/queuesize"

  case "${DATA_LINK}" in
    tap)
      log "データリンク: tap+vhost マルチキュー (queues=${DATA_QUEUES}, bridge=${BRIDGE})"
      setup_tap_link ;;
    vhostuser)
      log "データリンク: vhostuser (OVS-DPDK, queues=${DATA_QUEUES}, bridge=${OVS_BRIDGE})"
      setup_vhostuser_link ;;
    *)
      log "データリンク: socket back-to-back (単一キュー)" ;;
  esac

  start_vm tx        # socket時は listener
  sleep 2
  start_vm rx        # socket時は connector

  wait_ssh tx
  wait_ssh rx
  cmd_status
  log "準備完了。'vmlab.sh demo' で送受信デモを実行できます。"
}

# ---- デモ（送受信 + 実カウンタ） -----------------------------------------
# ethtool -S の複数キュー値を合算する awk（マルチキュー対応）
SUM_AWK='{for(i=1;i<=NF;i++)if($i ~ /^[0-9]+$/)s+=$i} END{printf "%d", s}'

# ethtool -S を 1 回だけ取得し、人間向け表示とキュー横断合算の両方に使う（ssh 往復を半減）
report_nic() {  # role  human_grep_re  queue_grep_re  sum_label
  local role="$1" human="$2" qre="$3" label="$4" stats
  stats="$(vm_ssh "${role}" "ethtool -S ${DATA_IF} 2>/dev/null" || true)"
  if [[ -z "${stats}" ]]; then   # 取得失敗と「カウンタが 0」を区別する
    echo '(取得不可)'
    printf '  -> %s: (取得不可)\n' "${label}"
    return
  fi
  grep -Ei "${human}" <<<"${stats}" || echo '(該当カウンタなし)'
  printf '  -> %s: ' "${label}"
  { grep -E "${qre}" <<<"${stats}" || true; } | awk "${SUM_AWK}"; echo
}

cmd_demo() {
  is_running tx || die "tx VM が起動していません。'vmlab.sh up' を実行してください。"
  is_running rx || die "rx VM が起動していません。'vmlab.sh up' を実行してください。"

  local xdperf="sudo /mnt/xdperf/bin/xdperf"
  local plugin_args="--plugin ${PLUGIN} --plugin-path /mnt/xdperf/bin"
  local cfg="{\"src_ip\":\"${TX_DATA_IP}\",\"dst_ip\":\"${RX_DATA_IP}\",\"dst_port\":10001,\"payload_size\":${DEMO_PAYLOAD},\"is_arp_resolve\":false}"

  local role
  # マルチキュー時(tap/vhostuser): combined チャンネル数をキュー数に合わせる（XDP TX/RX を多コアに分散）
  if [[ "${DATA_LINK}" == "tap" || "${DATA_LINK}" == "vhostuser" ]]; then
    log "マルチキュー: combined=${DATA_QUEUES} に設定（tx/rx）"
    for role in tx rx; do
      vm_ssh "${role}" "sudo ethtool -L ${DATA_IF} combined ${DATA_QUEUES} 2>&1 || true"
    done
  fi

  # NIC リング(descriptor)サイズを設定（rx=QUEUE_SIZE, tx=上限256にクランプ）
  local tx_qs; tx_qs="$(tx_ring_size)"
  log "リングサイズ: rx=${QUEUE_SIZE} / tx=${tx_qs} に設定（tx/rx VM とも。tx は virtio+vhost の上限256）"
  for role in tx rx; do
    vm_ssh "${role}" "sudo ethtool -G ${DATA_IF} rx ${QUEUE_SIZE} tx ${tx_qs} 2>&1 || true"
  done

  # 注意: pkill は -x（プロセス名の完全一致）を使う。-f だと ssh で渡す
  # コマンド文字列中の "xdperf" にマッチして自分の ssh セッションごと kill してしまう。
  log "rx: 受信モード起動（受信カウント = 実カウンタ）"
  vm_ssh rx "sudo pkill -x xdperf || true; \
    nohup ${xdperf} run --device ${DATA_IF} --send=false --recv \
    </dev/null >/tmp/xdperf-rx.log 2>&1 & echo started"
  sleep 2

  log "tx: 送信（${DEMO_SECONDS}秒）"
  vm_ssh tx "sudo pkill -x xdperf || true; \
    timeout ${DEMO_SECONDS} ${xdperf} run --device ${DATA_IF} ${plugin_args} \
    --count ${DEMO_COUNT} --parallelism ${DEMO_PARALLELISM} --infinite \
    --batch-size 64 --show-nic-stats --cfg '${cfg}' || true"

  sleep 1
  vm_ssh rx "sudo pkill -x xdperf || true"

  echo
  log "==== 送信側(tx) NIC カウンタ ===="
  report_nic tx 'xdp|tx_packets' 'tx_queue_[0-9]+_xdp_tx:' 'tx xdp_tx 合計'
  echo
  log "==== 受信側(rx) 受信ログ（末尾） ===="
  vm_ssh rx "tail -n 15 /tmp/xdperf-rx.log 2>/dev/null || echo '(ログなし)'"
  echo
  log "==== 受信側(rx) NIC カウンタ ===="
  report_nic rx 'xdp|rx_packets' 'rx_queue_[0-9]+_xdp_packets:' 'rx xdp_packets 合計'
}

# ---- 状態 / 停止 / 掃除 ---------------------------------------------------
pid_of() { local f="${CACHE_DIR}/$1.pid"; [[ -f "${f}" ]] && cat "${f}" || true; }
is_running() { local p; p="$(pid_of "$1")"; [[ -n "${p}" ]] && kill -0 "${p}" 2>/dev/null; }

cmd_status() {
  printf '  data-link: %s' "${DATA_LINK}"
  case "${DATA_LINK}" in
    tap)       printf ' (queues=%s, bridge=%s)' "${DATA_QUEUES}" "${BRIDGE}" ;;
    vhostuser) printf ' (queues=%s, ovs-bridge=%s, pmd=%s)' "${DATA_QUEUES}" "${OVS_BRIDGE}" "${PMD_CPU_MASK}" ;;
  esac
  printf ', ring=%s\n' "${QUEUE_SIZE}"
  for role in tx rx; do
    if is_running "${role}"; then
      printf '  %-3s : \033[1;32mrunning\033[0m (pid %s, ssh: ssh %s -i %s -p %s %s@127.0.0.1)\n' \
        "${role}" "$(pid_of "${role}")" "${SSH_OPTS[*]}" "${SSH_KEY}" "$(ssh_port_for "${role}")" "${GUEST_USER}"
    else
      printf '  %-3s : \033[1;31mstopped\033[0m\n' "${role}"
    fi
  done
}

cmd_ssh() {
  local role="${1:-tx}"
  is_running "${role}" || die "${role} VM が起動していません。"
  vm_ssh "${role}"
}

cmd_down() {
  for role in tx rx; do
    local p; p="$(pid_of "${role}")"
    if [[ -n "${p}" ]] && kill -0 "${p}" 2>/dev/null; then
      log "停止: ${role} (pid ${p})"
      kill "${p}" 2>/dev/null || true
    fi
    rm -f "${CACHE_DIR}/${role}.pid"
  done
  # 作った host 側リソースを撤去（socket モードでは no-op）
  case "${DATA_LINK}" in
    tap)       teardown_tap_link ;;
    vhostuser) teardown_vhostuser_link ;;
  esac
}

cmd_clean() {
  cmd_down || true
  log "overlay / seed / serial ログ / 状態ファイルを削除（ベースイメージは保持）"
  rm -f "${CACHE_DIR}"/*-overlay.qcow2 "${CACHE_DIR}"/*-seed.iso "${CACHE_DIR}"/*-serial.log "${CACHE_DIR}"/*.pid \
        "${CACHE_DIR}/datalink" "${CACHE_DIR}/dataqueues" "${CACHE_DIR}/queuesize" \
        "${CACHE_DIR}/bridge-created" "${CACHE_DIR}/pmd-cpu-mask.prev"
}

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

main() {
  local cmd="${1:-}"; shift || true
  case "${cmd}" in
    image)  cmd_image "$@" ;;
    up)     cmd_up "$@" ;;
    demo)   cmd_demo "$@" ;;
    status) cmd_status "$@" ;;
    ssh)    cmd_ssh "$@" ;;
    down)   cmd_down "$@" ;;
    clean)  cmd_clean "$@" ;;
    ""|-h|--help|help) usage ;;
    *) die "不明なサブコマンド: ${cmd}（--help 参照）" ;;
  esac
}

main "$@"
