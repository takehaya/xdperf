# XDPerf VM-to-VM テストラボ（自己完結 QEMU 版）

2 つの VM（`tx` 送信側 / `rx` 受信側）を QEMU の socket netdev で back-to-back 直結し、
**end-to-end の実カウンタ**（受信側の受信カウント・両側の NIC `ethtool -S`）で XDPerf を検証する再現環境。

```
            9p (ro)  out/                 9p (ro)  out/
              │                              │
        ┌─────┴─────┐   socket netdev  ┌─────┴─────┐
        │  tx VM    │  data NIC直結    │  rx VM    │
        │ 192.168.  │◄───────────────►│ 192.168.  │
        │ 1.1/24    │  (virtio-net)    │ 1.2/24    │
        └─────┬─────┘                  └─────┬─────┘
          mgmt│ user-net(hostfwd :2222)  mgmt│ :2223
              ▼                              ▼
                        host (ssh 制御)
```

## 前提ツール（host）

- `qemu-system-x86_64`, `qemu-img`
- `genisoimage`（cloud-init NoCloud seed ISO 生成）
- KVM（`/dev/kvm` に読み書きできること。必要なら `sudo chmod 0666 /dev/kvm` か kvm グループ参加）
- `curl`, `ssh`, `ssh-keygen`

Vagrant / Multipass / libvirt は不要（使わない）。

## 使い方

```shell
# 0) xdperf をビルド（9p で VM に渡す out/ を作る）
make build

# 1) ベースクラウドイメージを取得（初回のみ。既定: Ubuntu 24.04 cloud image）
scripts/vmlab/vmlab.sh image          # = make vmlab-image

# 2) 2VM 起動（cloud-init 完了 & 9p マウントまで待機）
scripts/vmlab/vmlab.sh up             # = make vmlab-up

# 3) 送受信デモ（rx で受信・tx で送信し、両側の実カウンタを表示）
scripts/vmlab/vmlab.sh demo           # = make vmlab-demo

# 4) VM に入る
scripts/vmlab/vmlab.sh ssh tx
scripts/vmlab/vmlab.sh ssh rx

# 5) 停止 / 掃除
scripts/vmlab/vmlab.sh down           # = make vmlab-down
scripts/vmlab/vmlab.sh clean          # overlay/seed/log 削除（ベースイメージは残す）
```

VM 内では `out/` が `/mnt/xdperf` に read-only マウントされる。xdperf は
`/mnt/xdperf/bin/xdperf`、プラグインは `--plugin-path /mnt/xdperf/bin` で参照する。
データ NIC は両 VM とも `data`（`set-name` で固定）。

## 主な設定（環境変数で上書き）

| 変数 | 既定 | 説明 |
|------|------|------|
| `VMLAB_BASE_IMAGE_URL` | Ubuntu 24.04 cloud image | ベースイメージ URL |
| `VMLAB_CPUS` / `VMLAB_MEM` | `4` / `4G` | VM の vCPU / メモリ |
| `VMLAB_DATA_LINK` | `socket` | データリンク方式: `socket`（自己完結・単一キュー）/ `tap`（host bridge+tap・vhost-net・マルチキュー）/ `vhostuser`（OVS-DPDK・PMDポーリング・マルチキュー） |
| `VMLAB_DATA_QUEUES` | `VMLAB_CPUS` と同値 | `tap`/`vhostuser` 時のキュー数（virtio mq / ethtool combined） |
| `VMLAB_QUEUE_SIZE` | `256` | NIC リング(descriptor)数。**rx は最大 1024、tx は上限 256 に自動クランプ** |
| `VMLAB_BRIDGE` | `xdpbr0` | `tap` 時の host bridge 名 |
| `VMLAB_OVS_BRIDGE` | `xdpovs0` | `vhostuser` 時の OVS-DPDK ブリッジ名 |
| `VMLAB_PMD_CPU_MASK` | `0x3c` | `vhostuser` 時の OVS-DPDK PMD コアマスク（0x3c = core 2-5 を busy-poll） |
| `VMLAB_HUGEPAGES_FORCE` | `0` | `vhostuser` で hugepage 不足時に `drop_caches`+自動確保（ホスト破壊的）を許可。既定は停止 |
| `VMLAB_SSH_PORT_TX` / `_RX` | `2222` / `2223` | host 側 ssh 転送ポート |
| `VMLAB_DATA_PORT` | `12345` | `socket` 時のデータ NIC 直結用 host TCP ポート |
| `VMLAB_PLUGIN` | `simpleudp.tinygo` | 送信に使う WASM プラグイン |
| `VMLAB_PARALLELISM` | `1` | 送信スレッド数（下記制約参照） |
| `VMLAB_PAYLOAD` / `VMLAB_COUNT` | `1200` / `10k` | ペイロード長 / パケットプール |
| `VMLAB_DEMO_SECONDS` | `8` | デモ送信秒数 |

`up` で使ったデータリンク方式は `.cache/vmlab/datalink` に記録され、`demo`/`down` が自動追従する。

### データリンク方式

| 方式 | リンク | キュー | sudo | 用途 |
|------|--------|--------|------|------|
| `socket`（既定） | QEMU socket netdev で 2VM 直結 | 単一 | 不要 | 自己完結・機能検証。到達 pps は host 律速で低い |
| `tap` | host bridge + multi_queue tap + vhost-net（kernel） | マルチ | 必要（bridge/tap 作成） | 負荷を上げたい時。kernel vhost-net が律速 |
| `vhostuser` | OVS-DPDK + vhost-user（userspace PMD ポーリング） | マルチ | 必要（OVS設定・hugepage） | 最も速い VM 間。PMD コア数で到達 pps がスケール |

```shell
# tap（kernel vhost-net）で負荷を上げる例
VMLAB_DATA_LINK=tap VMLAB_CPUS=8 make vmlab-up
VMLAB_PARALLELISM=8 VMLAB_DEMO_SECONDS=10 make vmlab-demo
make vmlab-down   # host bridge/tap も自動撤去

# vhostuser（OVS-DPDK）で更に速く（hugepage を食うので VM mem は小さめ推奨）
# hugepage が未確保なら VMLAB_HUGEPAGES_FORCE=1 で drop_caches+自動確保を許可（ホスト破壊的・任意）
VMLAB_DATA_LINK=vhostuser VMLAB_CPUS=8 VMLAB_MEM=2G VMLAB_HUGEPAGES_FORCE=1 scripts/vmlab/vmlab.sh up
VMLAB_PARALLELISM=8 VMLAB_DEMO_SECONDS=10 scripts/vmlab/vmlab.sh demo
scripts/vmlab/vmlab.sh down   # OVS bridge / hugepage subdir も自動撤去
```

実測比較（8 vCPU, 8 キュー, 1242B フレーム, 本リポジトリの開発機）:

| 指標 | `socket` | `tap`+vhost-net | `vhostuser`(OVS-DPDK, PMD 4 core) |
|------|----------|-----------------|-----------------------------------|
| 参考: 送信側生成 xmit/s | ~6 Mpps | ~28 Mpps | ~19.5 Mpps |
| **受信側 実受信**（rx の `recv/s` = 実カウンタ） | ~0.85 Mpps | ~2.9 Mpps | **~8.3 Mpps（≈84 Gbps）** |

> ヘッドラインは**受信側 VM が実際に数えた値**（rx の `recv/s`、`ovs-ofctl dump-ports` の vhu-rx tx）で見る。
> 送信側 `nic_tx_packets`（NIC 送出数）は受信側よりやや多くなる（OVS→rx 投入時の drop 分）。

到達 pps の律速は: `socket`=QEMUユーザ空間転送 → `tap`=kernel vhost-net の per-packet → `vhostuser`=OVS-DPDK PMD の転送能力。
`vhostuser` は **PMD コア（`VMLAB_PMD_CPU_MASK`）を増やすとさらに伸びる**。それ以上は実機 NIC / SR-IOV が必要。

### vhostuser（OVS-DPDK）の前提

- `openvswitch-switch-dpdk` 導入済み＋ `ovs-vsctl get Open_vSwitch . dpdk_initialized` が `true`（= `other_config:dpdk-init=true`）。
- hugepages: ゲストメモリ全体を共有 hugepage に載せる。VM mem は 2G など小さめ推奨。事前に必要数を確保しておくこと。不足している場合、`VMLAB_HUGEPAGES_FORCE=1` を指定したときだけ `up` が `drop_caches`+`compaction`+自動確保を行う（ホスト全体のページキャッシュを捨てる破壊的操作のため既定では停止する）。
- QEMU が vhost-user の **server**（ソケットは `.cache/vmlab/` に user 所有で作成）、OVS が `dpdkvhostuserclient` で接続。これで root 所有ソケットの権限問題を回避。
- QEMU は `/dev/hugepages/xdperf`（user 所有サブディレクトリ）から hugepage を確保。
- PMD スレッドは指定コアを 100% busy-poll する。

> カウンタ注意: `ethtool -S` のキュー値は実行間で積算される。1 回あたりの到達数は
> xdperf の `nic_tx_packets`（差分計測）と受信側の `recv/s` レートで見るのが正確。
> OVS 側は `sudo ovs-ofctl dump-ports <ovs-bridge>` でも確認できる。

## 制約・注意（重要）

- **いずれの方式でも、1 台の host 内 VM-to-VM では到達 pps はソフトウェア転送が律速**で、
  送信側の XDP_LIVE_FRAME 生成レート（実機で語る数十 Mpps 級）より低くなる。
  - `socket`: QEMU のユーザ空間転送＋単一キューが律速（到達 ~1 Mpps 級）。データ経路の `--parallelism` は 1 が現実的。
  - `tap`: kernel vhost-net＋マルチキューで改善するが、vhost-net の per-packet コスト（到達 ~3 Mpps 級）が上限。
  - `vhostuser`: OVS-DPDK の PMD ポーリングで更に改善。PMD コア数で受信 pps がスケールする（実測・**受信側 実カウンタ**: PMD 4 コア=受信 ~8.3 Mpps、PMD 8 コア=受信 ~15.1 Mpps/≈145 Gbps）。`VMLAB_PMD_CPU_MASK` で調整。
    - キュー数=8 なら PMD 8 コアが ingest 側の上限（vhu-tx の 8 キューを 1 本ずつ分担）。それ以上 PMD を増やしても効果は薄い。
    - PMD 8 コアでは送信側 tx-ring drop が 54%→14% に低下し、**律速は xdperf の生成側（guest vCPU/キュー）**に移る。更に伸ばすなら guest コア/キューを増やす。
    - 受信総数は送信側 `nic_tx_packets` よりやや少ない（OVS→rx 投入 drop 分）。必ず受信側で測ること。
  - それ以上の到達レートが要るなら実機 NIC / SR-IOV が必要。
- **NIC リングサイズ（`VMLAB_QUEUE_SIZE`）の拡大は、この VM ラボではほぼ効かない**:
  `tx_queue_size` は virtio-net+vhost-net で 256 が上限（QEMU が拒否）で、溢れている TX 側リングを大きくできない。
  RX リングは 1024 まで上げられるが RX はボトルネックではないため、到達 pps は実測でほぼ不変だった。
  リング/キュー調整が本当に効くのは実機 NIC（`docs/ja/tips.md` 参照。実機 ICE では TX リングをむしろ 256 に下げる方が速かった例もある）。
- 本ラボの価値は **end-to-end の機能・正当性検証**（実際に届く / 受信側がカウントする /
  チェックサム正当 / echo 応答）と **誰でも再現できること**。
  スループットのヘッドライン値は、別途**送信側 NIC の `xdp_tx`／`nic_tx_packets` カウンタ**（＝生成・送出能力）で取るのがよい。
- 生成物（overlay qcow2 / seed ISO / serial ログ / ベースイメージ）と状態ファイルは `.cache/vmlab/` に置かれ、
  Git 追跡対象外（リポジトリルートの `.gitignore` 参照）。
