# `veth` 上のパケット送出機構 8 種の比較および `veth` vs `netkit`（単一ホスト・100GbE・400GbE・K8s/Cilium）実測と推奨トポロジ

> **English version**: [docs/en/benchmarks/netkit-and-veth-io/README.md](../../../en/benchmarks/netkit-and-veth-io/README.md)

## 要約

`veth` と `netkit` は、コンテナや Kubernetes の Pod をホストにつなぐ仮想デバイスである。この文書は、XDP を使うトラフィックジェネレータ xdperf による測定結果と、測定環境の組み方を記録したものである。

1. **xdperf は `veth` ペア上で、ほかの 7 種の送信手段より 5.4〜22 倍速い（1 章）。** 送信 1 コア、64 B の UDP で、xdperf は 9.56 Mpps を記録した。2 位の `AF_XDP`（コピーモード）は 1.78 Mpps であった。ほかの 7 種は 1 パケットごとに `sk_buff` を確保する。xdperf は `sk_buff` を確保せず、カーネル内のフレームを再利用する。`netkit` ペアへの直接送信では、`AF_XDP` とカーネルの `pktgen` はともに 1.66 Mpps であった。
2. **受信 Pod の境界を `netkit` に替えると、xdperf による測定では `veth` との速度差がはっきり表れる（2 章）。** `iperf3` の既定設定では、GSO/GRO がセグメントを束ねる。そのため、`netkit` の速度向上は +4% にとどまり、ばらつきに埋もれる。xdperf は、束ねられないセグメントを複数フローで流せる。`netkit` は `veth` より、単一ホストで +16〜32%、100GbE 実機で +25〜35%、400GbE 実機で +5〜10% 速かった。400GbE では受信アプリケーションが先に上限に達するため、速度差は小さい。`netkit` の短命 TCP の毎秒接続数（CPS）は、400GbE で `veth` に対して +46% であった。受信経路へのフロー別集計用 BPF プログラムの追加による速度低下は、誤差の範囲であった。GRO がセグメントを束ねない条件では、BPF プログラムの集計値は全フローで xdperf のフロー別送信記録と一致した。
3. **xdperf は `netkit` を送信デバイスにできない（3 章）。** `netkit` は XDP フレームの送信（`.ndo_xdp_xmit`）を実装していない。この文書は、送信側に `veth` か物理 NIC を使い、受信 Pod の境界だけを差し替える構成を推奨する。3 章は、単一ホスト、実機 2 ノード、Kubernetes + Cilium の構成を示す。3.3 節の早見表は、Cilium で必要な設定をまとめている。
4. **`veth` での xdperf の送信性能は、キュー数と worker 数にほぼ比例して伸びる（3.4 節）。** 32 キュー、32 worker で、xdperf は UDP で 301.5 Mpps、TCP で 225.7 Gbps を記録した。TCP の再送は 0 であった。CNI が作る `veth` は 1 キューである。`veth` のキュー数は、Pod の起動後に `ethtool -L` で増やせる。Pod に CPU 制限がある場合、worker 数、CPU の指定、キュー数が制限に合わないと、xdperf の送信性能は大きく落ちる。

## この文書の内容

コンテナ・Kubernetes データパス（`veth` および `netkit`）における以下の 4 点を記録する。

1. **`veth` / `netkit` 1 コアにおける Linux 全 8 種のパケット送出機構の比較（`n=5` 反復、[veth_io_summary.csv](veth_io_summary.csv)）**:
   - `xdperf`（`BPF_F_TEST_XDP_LIVE_FRAMES` + カーネル内 XDP Diff）と、`AF_XDP`（`XDP_COPY`）、`io_uring`（`IORING_OP_SEND`）、`AF_PACKET`（`sendmmsg` / `send()` / `PACKET_MMAP`）、カーネル標準 `pktgen`（`pktgen.ko`）、標準 UDP ソケット（`sendmmsg`）の同一条件比較、および `netkit` 直接送信時に現れる「`sk_buff` 割り当ての壁（1.66 Mpps）」。
2. **`veth` vs `netkit`（`netkit-l2` / `netkit-l3` / `netkit-bpf`）および 5-Tuple `LRU_HASH` カウンタの単一ホスト（`n=5`）・100GbE（ConnectX-5）・400GbE（ConnectX-7）実測（[netkit_summary.csv](netkit_summary.csv)）**:
   - `iperf3`（GSO/GRO ON vs OFF）と `xdperf` の対照、標準 `ip_id: "flow"` でのフロー数スケーリングと送信側 GRO 制御（`ip_id: "shared"`）、短命 TCP（CPS）における `/proc/net/softnet_stat` 理論値一致（`13.00 → 10.00` 回/接続）、高 PPS UDP フラッド＋TCP 混合、および 5-tuple `LRU_HASH`（65,536 エントリ）の負荷と `--tcp-flow-report` 送信記録照合。
3. **単一ホスト・実機 100G/400G・Kubernetes + Cilium（`datapathMode=veth` / `netkit`）における推奨実験トポロジと必須設定**:
   - なぜ送信側を `.ndo_xdp_xmit` 対応デバイスに置く非対称トポロジが必要か、および Cilium 環境でハマりやすい設定（`lxc*` の GRO、`--xdp-mode generic`、`socketLB.hostNamespaceOnly`、`hostNetwork` / `CiliumNodeConfig`）の早見表。
4. **マルチキュー `veth` のスケーリングと Kubernetes Pod での注意点（3.4 節）**:
   - `veth` のキュー数と `xdperf` の worker 数を `1` から `32` まで増やしたときの UDP と TCP の送信性能、CNI が作成した 1 キューの `veth` を Pod の起動後に `ethtool -L` でマルチキュー化する手順と効果、および cgroup の CPU 制限（CFS クォータ、`cpuset.cpus`）がある Pod での挙動と対策。

再現スクリプトは [docs/ja/scripts/bench_veth_io.sh](../../scripts/bench_veth_io.sh)、[docs/ja/scripts/bench_netkit.sh](../../scripts/bench_netkit.sh)、[docs/ja/scripts/bench_netkit_realnic.sh](../../scripts/bench_netkit_realnic.sh) に収録している。

---

## 1. `veth` 1 コアにおける Linux 全 8 種のパケット送出機構の比較 (`n=5`)

### 1.1 測定条件
- **測定環境**: Intel Xeon 6746E（64 vCPU, NUMA 1 ノード）、Linux `6.17.0-41-generic`
- **トポロジ**: 2 つの network namespace（`io-tx` ↔ `io-rx`）を 1 キューの `veth` ペア（`vtx` ↔ `vrx`）で直結。対向 `vrx` には `xdperf run --recv`（Native XDP `XDP_DROP`）をアタッチし、受信側ソケット層のボトルネックを排除した状態で送信側 1 コア（`taskset -c 2`）の純粋な最大送出 PPS を比較。
- **ワークロード**: L2 フレーム長 64 B（Eth 14 B + IPv4 20 B + UDP 8 B + Payload 22 B、FCS 除く）。毎パケット UDP 送信元ポートを `10000`〜`26383` の **16,384 通り** にスイープ（各ラウンド `n=5` 反復、平均 ± 標本標準偏差 SD）。

### 1.2 実測結果（[veth_io_summary.csv](veth_io_summary.csv)）

| 順位 | パケット送出機構 | `veth` 上でのカーネル内部経路 | 送出 PPS (平均 ± SD, `n=5`) | 1 パケットあたり CPU 時間 | 64B 帯域換算 | `xdperf` 倍率 |
|---:|---|---|---:|---:|---:|---:|
| **1** | **`xdperf`<br>(`BPF_F_TEST_XDP_LIVE_FRAMES` + In-Kernel XDP Diff)** | **カーネル内 `page_pool` の `xdp_frame` を `sk_buff` 確保なし・ユーザー空間コピーなしで直接リサイクル → `veth_xdp_xmit`** | **`9,557,197 ± 136,988 PPS`** | **`104.6 ns`** | **`4.893 Gbps`** | **基準 (`1.00x`)** |
| **2** | **`AF_XDP`<br>(`XDP_COPY`, batch=64)** | `XDP_ZEROCOPY` は `errno=95 (EOPNOTSUPP)` で拒否。<br>UMEM から毎パケット `sk_buff` 確保＋コピー (`xsk_generic_xmit`) | `1,776,021 ± 18,321 PPS` | `563.1 ns` | `0.909 Gbps` | **`xdperf` が 5.38 倍高速** |
| **3** | **`io_uring`<br>(`IORING_OP_SEND`, batch=64 + `QDISC_BYPASS`)** | SQE 64 個バッチ投入、カーネル内で毎パケット `sk_buff` 確保＋ユーザー空間からコピー | `1,435,004 ± 37,477 PPS` | `696.9 ns` | `0.735 Gbps` | **`xdperf` が 6.66 倍高速** |
| **4** | **`AF_PACKET`<br>(`sendmmsg`, batch=64 + `QDISC_BYPASS`)** | 64 個バッチ syscall、毎パケット `sk_buff` 確保＋ユーザー空間からコピー | `1,295,598 ± 28,444 PPS` | `771.8 ns` | `0.663 Gbps` | **`xdperf` が 7.38 倍高速** |
| **5** | **`AF_PACKET`<br>(`send()` + `PACKET_QDISC_BYPASS`)** | 毎パケット syscall＋`sk_buff` 確保＋ユーザー空間からコピー | `1,273,179 ± 3,529 PPS` | `785.4 ns` | `0.652 Gbps` | **`xdperf` が 7.51 倍高速** |
| **6** | **`AF_PACKET`<br>(`PACKET_MMAP` / `TPACKET_V2` `TX_RING` + `QDISC_BYPASS`)** | 共有リングから `tpacket_snd()` で毎パケット `sk_buff` 確保＋コピー | `1,251,056 ± 25,586 PPS` | `799.3 ns` | `0.641 Gbps` | **`xdperf` が 7.64 倍高速** |
| **7** | **カーネル標準 `pktgen`<br>(`pktgen.ko`, 16,384 ポートスイープ, `clone_skb 0`)** | 100% カーネルスレッド (`kpktgend`) 内だが、可変ヘッダー生成のたびに `pktgen_alloc_skb()`＋チェックサム計算＋`veth_xmit` (SKB 経路) | `632,570 ± 3,900 PPS` | `1,580.9 ns` | `0.324 Gbps` | **`xdperf` が 15.11 倍高速** |
| **8** | **標準 UDP ソケット<br>(`AF_INET` `SOCK_DGRAM` + `sendmmsg` batch=64)** | UDP/IP スタック横断＋毎パケット `sk_buff` 確保＋コピー | `425,993 ± 5,630 PPS` | `2,347.5 ns` | `0.218 Gbps` | **`xdperf` が 22.44 倍高速** |

### 1.3 カーネル内部コードパスによるナノ秒単位の考察（なぜ `xdperf` が `AF_XDP` より 5.38 倍高速なのか）

1. **`xdperf`（`104.6 ns / pkt` = `9.56 Mpps`）の内部経路**:
   - `net/bpf/test_run.c` の `bpf_test_run_xdp_live()` は、カーネル内の `page_pool` から確保した `xdp_frame` を 64 パケット単位でバッチ処理し、1 回の `bpf_prog_test_run_opts` システムコール内で何百万回もインプレースでリサイクルする。
   - **システムコールは 1 回のみ、`struct sk_buff` の確保（`kmem_cache_alloc`）は 0 回、ユーザー空間とのメモリコピーも 0 回** である。
   - 各イテレーションでは L1 キャッシュ上のベースパケットに対して XDP プログラム（`xdp_tx`）が事前計算済みの `DiffEntry`（2 バイトのポート番号＋2 バイトのキャッシュ済みチェックサム差分）を上書きし（約 15〜20 ns）、`veth_xdp_xmit()` で対向の `xdp_ring` に直接ポインタを積み、対向の `XDP_DROP` が即座に `page_pool` のキャッシュリングへページを返却（`__page_pool_put_page`）する。
2. **`AF_XDP` `XDP_COPY`（`563.1 ns / pkt` = `1.78 Mpps`、差分 `+458.5 ns / pkt`）の内部経路**:
   - 仮想デバイスである `veth` はハードウェア DMA リングを持たないため、`XDP_ZEROCOPY` を指定して `bind()` すると `errno=95 (EOPNOTSUPP)` で失敗し、必ず `XDP_COPY` モード（`net/xdp/xsk.c` の `xsk_generic_xmit()`）にフォールバックする。
   - `xsk_generic_xmit()` は名前に `xsk`（XDP ソケット）と付いているものの、**送信経路の実態は `xdp_frame` ではなく通常の `sk_buff` 送信経路** である。すなわち毎パケット以下の 4 段階を実行する：
     1. `sock_alloc_send_pskb()` による **`struct sk_buff` のメモリ確保と初期化、ソケット送信バッファ（`sk_wmem_alloc`）の原子加算**（約 150 ns）
     2. ユーザー空間 UMEM からカーネル `skb->data` への **`memcpy`（`skb_store_bits`）と `skb_destructor`（`xsk_destruct_skb`）の設定**（約 70 ns）
     3. `dev_direct_xmit()` → **`veth_xmit(skb)`（XDP 直結の `veth_xdp_xmit` ではなくレガシーな SKB キュー経路）** の呼び出しと、対向 `veth_xdp_rcv_skb()` での **`sk_buff` → `xdp_buff` 変換**（約 180 ns）
     4. 対向での `kfree_skb()` → `xsk_destruct_skb()` による UMEM Completion Ring の更新と、64 パケットごとの `sendto()` システムコール境界横断（約 60 ns）
   - これら 4 つのコストの合計（約 `+460 ns/pkt`）が `104.6 ns` に加算されることで `563.1 ns/pkt`（`1.78 Mpps`）となる。
3. **`io_uring`（`696.9 ns/pkt`）や `AF_PACKET`（`771.8〜799.3 ns/pkt`）が 1.25〜1.44 Mpps に密集する理由**:
   - `io_uring`、`sendmmsg`、`PACKET_MMAP` はいずれもシステムコール回数を 64 分の 1 に減らすが、カーネル内部（`packet_snd` / `tpacket_snd`）で **「毎パケット `alloc_skb` してユーザー空間からコピーし、`veth_xmit(skb)` に流して `kfree_skb` する」** という支配的ボトルネック（約 500〜600 ns/pkt）が `AF_XDP (XDP_COPY)` と共通しているため、すべて 1.25〜1.78 Mpps の帯域に収束する。
   - なお DPDK の仮想 PMD（`--vdev=net_af_xdp` / `--vdev=net_af_packet`）や `Netmap` の `veth` generic（エミュレーション）モードも、カーネル境界では上記の `xsk_generic_xmit` または `tpacket_snd` / `alloc_skb` を呼ぶため、同じ上限に従う。

### 1.4 同じ送出機構を `netkit` ペア（`nktx` ↔ `nkrx`）に直接適用した場合の挙動と「`sk_buff` の壁（1.66 Mpps）」

続いて、同じホスト（`400g-1.lab`、CPU 2 固定、64B UDP、16,384 ポートスイープ）上で、`veth` ペアを **`netkit` ペア（`ip link add nktx type netkit mode l2 peer nkrx`、対向 `nkrx` は TC ingress で drop）** に置き換えて直接送信した場合の実測値を比較する：

| パケット送出機構 | `veth` 1 コア PPS | `netkit` 直接送信 1 コア PPS | `veth` → `netkit` での変化とカーネル内部の理由 |
|---|---:|---:|---|
| **`xdperf` (`BPF_F_TEST_XDP_LIVE_FRAMES`)** | **`9,557,197 PPS`** | **直接送信は不可**（Phase 0 ガードレールで即拒否） | `netkit`（`drivers/net/netkit.c`）は `.ndo_bpf` と `.ndo_xdp_xmit` を実装していない（`xdp_features = 0`）ため、`netkit` 自体からは `xdp_frame` を送出できない。したがって `netkit` を試験する際は **「対向の `veth` / 物理 NIC から `xdperf` で送信し、`TCX ingress`（`bpf_redirect_peer`）で `netkit` に流し込む非対称構成」** が必須となる。 |
| **`AF_XDP` (`XDP_COPY`, batch=64)** | `1,776,021 PPS` | **`1,658,604 PPS`** (`zc_errno=95`) | `netkit` でも `XDP_ZEROCOPY` は `errno=95 (EOPNOTSUPP)` で拒否され、`xsk_generic_xmit`（毎パケット `alloc_skb` ＋ UMEM コピー）に落ちるため **1.66 Mpps（`602.9 ns/pkt`）** が上限となる。 |
| **カーネル標準 `pktgen` (`pktgen.ko`, 16,384 ポートスイープ)** | `632,570 PPS` | **`1,658,527 PPS` (+162% 高速化)** | `veth` では対向に XDP がアタッチされていると `veth_xmit(skb)` の先で `veth_xdp_rcv_skb()` の変換コストがかかっていたが、`netkit_xmit(skb)` は `sk_buff` をそのままインラインで peer へ渡すため **2.62 倍** に高速化し、**`AF_XDP (XDP_COPY)` と完全に同じ `1.66 Mpps`（`602.9 ns/pkt`）に収束**する。 |
| **`io_uring` (`IORING_OP_SEND`, batch=64)** | `1,435,004 PPS` | **`1,274,201 PPS`** | `alloc_skb` ＋ ユーザー空間からのコピーにより約 1.27 Mpps で頭打ち。 |
| **`AF_PACKET` (`sendmmsg`, batch=64)** | `1,295,598 PPS` | **`1,184,044 PPS`** | 同上（約 1.18 Mpps）。 |
| **`AF_PACKET` (`send()`)** | `1,273,179 PPS` | **`1,174,318 PPS`** | 同上（約 1.17 Mpps）。 |
| **`AF_PACKET` (`PACKET_MMAP` / `TPACKET_V2`)** | `1,251,056 PPS` | **`1,123,843 PPS`** | 同上（約 1.12 Mpps）。 |
| **標準 UDP ソケット (`AF_INET` + `sendmmsg` batch=64)** | `425,993 PPS` | **`886,326 PPS` (+108% 高速化)** | `netkit_xmit(skb)` によるデバイス境界の軽量化で通常の UDP ソケットも **2.08 倍** に高速化するが、UDP/IP スタック＋`alloc_skb` により 88.6 万 PPS が上限となる。 |

* **`netkit` 直接送信実験から分かる重要な結論**:
  1. **`netkit` ペアへの直接送信では、`AF_XDP (XDP_COPY)` の送信速度は `1,658,604 PPS`、カーネル内 `pktgen` の送信速度は `1,658,527 PPS`（いずれも `1.66 Mpps` = `603 ns/pkt`）であった。** `AF_XDP (XDP_COPY)` はユーザー空間から送信する。`pktgen` はカーネル内で送信する。両者は、1 パケットごとに `struct sk_buff` を確保して解放する。経路が異なる両者の送信速度が同じ値になったことから、この構成では `struct sk_buff` の確保と解放が送信速度の上限を決めていると考えられる。本書は、`netkit` 上のこの上限を「`sk_buff` 割り当ての壁」と呼ぶ。ただし、`1.66 Mpps` は `netkit` ペアでの実測値であり、デバイスによらない上限ではない。`veth` ペア上の `AF_XDP (XDP_COPY)` の送信速度は `1.78 Mpps`（1.2 節）であり、`1.66 Mpps` を上回る。両ペアでは、対向でのパケット破棄方法も異なる。`veth` ペアでは、対向の Native XDP が `XDP_DROP` でパケットを破棄する。`netkit` ペアでは、対向の TC ingress がパケットを破棄する。1 パケットごとに `sk_buff` を確保する 7 種の送信手段は、どちらのデバイスでも 1 コアあたり `1.8 Mpps` 未満にとどまった。
  2. 一方、`netkit` 自体は `.ndo_xdp_xmit` を持たないため、`netkit` 上で直接 `sk_buff` をバイパスすることはできない。だからこそ、「送信側は `.ndo_xdp_xmit` を持つ `veth` や物理 NIC 上の `xdperf`（`page_pool` + `xdp_frame` で `sk_buff` の壁を突破）で駆動し、受信側 Pod の `netkit` へ `bpf_redirect_peer` で流し込む」という非対称トポロジが技術的に理にかなっている。

---

## 2. `veth` vs `netkit` および 5-Tuple `LRU_HASH` カウンタの実測結果（単一ホスト・100GbE・400GbE）

集計データは [netkit_summary.csv](netkit_summary.csv) に収録している。

### 2.1 単一ホスト 64 vCPU における `n=5` 反復測定（平均 ± SD）

1. **`iperf3`（GSO/GRO ON vs OFF）と `xdperf` の直接対照**:
   - 既定の `iperf3 -P 4`（GSO/GRO ON）では 64 KiB の super-skb に束ねられるため `Softnet/seg`（`/proc/net/softnet_stat` 処理回数 / 1448B セグメント数）が **`0.05〜0.06`** まで低下し、`veth`（`144.36 ± 3.44 Gbps`）と `netkit-bpf`（`150.26 ± 2.87 Gbps`）の差は **`+4.12% ± 2.89 pt`** に隠れる。
   - `xdperf` は受信側オフロード設定に一切触れずに非集約セグメント負荷（`Softnet/seg = 2.51 → 2.00`）を生成し、`1w/16f` で **`+16.71% ± 1.40 pt`**、`4w/64f` で **`+19.90% ± 1.18 pt`** の差を分離できる。
2. **標準の `ip_id: "flow"`（フロー別連番）のまま並行フロー数を増やした際のスケーリング（`n=5`）**:
   - `1w / 1f (win=16)`: `veth` `256,046 ± 4,112` vs `netkit-bpf` `260,000 ± 4,155 segs/s`（**`+1.55% ± 0.65 pt`**、`Softnet/seg = 0.65 → 0.54`、単一フローは GRO で集約）
   - `1w / 16f (win=8)`: `veth` `225,852 ± 1,566` vs `netkit-bpf` `262,939 ± 2,194 segs/s`（**`+16.42% ± 0.62 pt`**、`Softnet/seg = 2.51 → 2.00`）
   - `1w / 64f (win=2)`: `veth` `227,319 ± 3,140` vs `netkit-bpf` `265,610 ± 3,358 segs/s`（**`+16.85% ± 1.07 pt`**、`Softnet/seg = 2.51 → 2.00`）
   - `1w / 128f (win=1)`: `veth` `309,725 ± 2,383` vs `netkit-bpf` `388,782 ± 2,775 segs/s`（**`+25.53% ± 0.45 pt`**、`Softnet/seg = 3.00 → 2.00`）
   - `4w / 256f (win=1)`: `veth` `1,140,744 ± 12,554`（`13.21 Gbps`） vs `netkit-bpf` `1,505,644 ± 21,632 segs/s`（`17.44 Gbps`、**`+31.99% ± 0.67 pt`**、`Softnet/seg = 2.98 → 2.00`）
3. **5-Tuple `LRU_HASH`（65,536 エントリ）カウンタのオーバーヘッド（`n=5`）**:
   - `1w / 16f`: 低下率 **`+0.41% ± 3.16 pt`**
   - `4w / 64f`: 低下率 **`+0.64% ± 3.59 pt`**
   - `4w / 256f`: 低下率 **`+0.35% ± 2.41 pt`**（256 tuple 完全一致）
   - `4w / 1,024f`: 低下率 **`+0.87% ± 0.90 pt`**（`1.31 Mpps` / `15.1 Gbps`、1,024 tuple 完全一致）
   - `高 CPS 連続新規 tuple 挿入 (4w / 256 スロット, 1 KiB/conn, 3s)`: 低下率 **`-6.72% ± 12.67 pt`**（3 秒間で平均 **`44,479` 件** の新規エフェメラル 5-tuple を挿入し、全 5 ラウンドで完了接続数と ingress/egress のユニーク tuple 数が **100% 完全一致**）

### 2.2 実機 100GbE（ConnectX-5）および 400GbE（ConnectX-7）2 ノード測定の要点

- **100GbE ConnectX-5（`zh2.lab` ↔ `zh3.lab`, AMD EPYC 7282 16C, Linux `7.0.0-38-generic`）**:
  - 持続 TCP（`4w / 64f`）において、`ip_id: "flow"` で `veth` `53.188 Gbps` → `netkit-bpf` **`66.692 Gbps (+25.4%)`**、送信側 GRO 抑制（`ip_id: "shared"`）で `1w/16f` **`+24.5%`**・`4w/64f` **`+32.3%`**・`8w/256f` **`+35.2%`**。
  - 短命 TCP（CPS）で受信側 `Softnet/conn` が `veth` の **`13.00 回/接続`** から `netkit-bpf` の **`10.00 回/接続`** に理論値どおり減少し、250k PPS の UDP フラッド＋4 TCP 混合（`mixed.go`）では TCP 再送が **`408 → 184 回 (-54.9%)`**、完了時間が **`8.901s → 3.451s (-61.2%)`** に短縮。
- **400GbE ConnectX-7（`ipa-02-400g` ↔ `ipa-01-400g`, Core i9-12900K 24C, Linux `6.8.0-147-generic`）**:
  - 持続 TCP（`4w / 64f`）において、再送 0 のまま `veth` `105.422 Gbps` → `netkit-bpf` **`110.423 Gbps`（`9,532,398 segs/s`、`+4.7%`）**、`ip_id: "shared"` で `82.097 Gbps` → **`90.623 Gbps (+10.4%)`**（110 Gbps 付近の上限は受信側単一プロセス `xdperf-sink` のソケット `read()` と受信 `ksoftirqd` の CPU 共有律速）。
  - 短命 TCP（CPS, `4w / 256s`）で `veth` `18,549.2 CPS`（`Softnet/conn = 13.01`）→ `netkit-bpf` **`27,050.4 CPS (+45.8%)`**（`Softnet/conn = 10.00`）。
  - 110 Gbps（950 万 segs/s）領域での 5-tuple `LRU_HASH` カウンタのオーバーヘッドは **`-0.3%`（`110.247 → 109.868 Gbps`）** と誤差範囲内であり、`window_segs=1`（128/256 フロー）および UDP+TCP 混合（35,412 パケット）で `--tcp-flow-report` の送信記録と **100%（不一致 0）完全一致**した。

---

## 3. 推奨実験トポロジ（単一ホスト・実機 100G/400G・Kubernetes + Cilium）

1.4 節で示したとおり、`netkit` は `sk_buff` の転送は高速だが `.ndo_xdp_xmit` を持たないため、`netkit` 自体を送信デバイスにすると `1.66 Mpps`（`sk_buff` 割り当ての壁）を超えられず、`xdperf`（`BPF_F_TEST_XDP_LIVE_FRAMES`）による直接送信もできない。

そのため、データパスや BPF プラグインを評価する際は、**「送信側（Load Generator）は常に `.ndo_xdp_xmit` を持つデバイス（`veth` / 物理 NIC / SR-IOV VF）に置いて `sk_buff` の壁を超えた負荷を生成し、テスト対象（DUT）側の Pod 境界だけを `veth` と `netkit` で差し替える『非対称トポロジ』」** を基本とする。

### 3.1 パターン 1：単一ホスト（ローカル netns / CI）での 3-Namespace 非対称トポロジ

[docs/ja/scripts/bench_netkit.sh](../../scripts/bench_netkit.sh) および [examples/tcp-netkit/](../../../../examples/tcp-netkit/README.md) で採用している構成。

```
+-------------------+      +----------------------------------------+      +-----------------------+
|  送信側 (b-tx)    |      |         DUT ホスト / Node (b-dut)      |      |  受信側 Pod (b-rx)    |
|  [Load Generator] |      |                                        |      |  [Target Workload]    |
|                   |      |  (1) 入口フック         (2) Pod 出口   |      |                       |
|  xdperf           | veth |  vdut:                  edut:          |      |  erx:                 |
|  (LIVE_FRAMES +   |======|  ・pass-through XDP     ・veth または  |======|  ・xdperf-sink        |
|   In-Kernel TCP)  | vtx  |  ・TCX ingress          ・netkit       |      |    (または responder) |
|                   |      |   (bpf_redirect_peer     (BPF_NETKIT_  |      |                       |
|  ※ ここは常にveth |      |    + 往路 5-tuple 計数)   PEER 復路計数)|      |  ※ ここだけ差し替える |
+-------------------+      +----------------------------------------+      +-----------------------+
        ▲                                      ▲
        │                                      │
  [送信記録 CSV] ────── 1対1 答え合わせ ───────┘
 (--tcp-flow-report)    (往路: tx_pkts + rx_replies == TCX ingress)
                        (復路: rx_pkts              == BPF_NETKIT_PEER)
```

- **設計の要点**:
  1. 送信側（`vtx` ↔ `vdut`）はマルチキュー `veth`（`numtxqueues 8 numrxqueues 8`）に固定し、`vdut` に `pass-through XDP`（`-xdp-pass-dev vdut`）をアタッチして `veth_xdp_xmit` の NAPI パスを有効化する。
  2. 受信側境界（`edut` ↔ `erx`）だけを `veth` / `netkit-l2` / `netkit-l3` / `netkit-bpf` で差し替えることで、送信条件を 100% 揃えたまま受信側境界の純粋な差を測定できる。
  3. スループット（Goodput / CPS）と同時に `/proc/net/softnet_stat`（`Softnet/seg`, `Softnet/conn`）と `--tcp-flow-report` を取得し、backlog キュー通過回数と全フローの計数一致を同時に検証する。

### 3.2 パターン 2：実機 2 ノード（100GbE / 400GbE）での非対称トポロジ

[docs/ja/scripts/bench_netkit_realnic.sh](../../scripts/bench_netkit_realnic.sh) で採用している構成。

```
+----------------------------+            +----------------------------------------------------+
| 送信ノード (Node 1)        |            | 受信 DUT ノード (Node 2)                           |
|                            |            |                                                    |
|  xdperf (Native XDP)       | 100G/400G  | 物理 NIC (mlx5 等)          受信 Pod netns (b-rx)  |
|  ・ip_id: "flow" (GRO ON)  |============| ・TCX ingress          edut  erx:                  |
|  ・ip_id: "shared"(GRO抑制)|  物理リンク|  (bpf_redirect_peer   ====== ・xdperf-sink         |
|  ・--tcp-flow-report       |            |   + 往路 5-tuple 計数)  ▲    (または --tcp-server) |
+----------------------------+            |                         │                          |
                                          |                BPF_NETKIT_PEER                     |
                                          |               (bpf_redirect_neigh + 復路計数)      |
                                          +----------------------------------------------------+
```

- **設計の要点**:
  1. 物理 NIC（`mlx5_core` 等）は NAPI GRO が強力なため、少数フローで `ip_id: "flow"` のみを流すと入口で 8〜10 セグメントが 1 つの super-skb に束ねられ、後段の `veth` vs `netkit` の差が隠れる。**受信側（DUT）の `ethtool` オフロード設定には一切触れず、送信側の `ip_id: "flow"`（GRO 有効）と `ip_id: "shared"`（GRO 抑制）または並行フロー数（1 → 256 本）を切り替えて両方測定する**。
  2. Linux ソケットアプリまでの E2E 性能を測る場合は `xdperf-sink` を、ソケット層の `read()` CPU 律速（約 110 Gbps）を超えてデータパス自体の上限を測る場合は `xdperf --tcp-server`（XDP レスポンダ）や複数リスナーを対向に置く。

### 3.3 パターン 3：Kubernetes + Cilium 環境での推奨トポロジと必須設定

Kubernetes クラスタ上で Cilium を動かしている場合、Cilium の `bpf.datapathMode` が **`veth`（既定）** か **`netkit`（`netkit` / `netkit-l2`）** かによって以下の構成を採る。

#### (A) Cilium `bpf.datapathMode=veth`（標準モード）の場合
送信側・受信側ともに通常の Kubernetes Pod（別ワーカーノードに配置）としてデプロイし、送信 Pod 内の `eth0 (veth)` から直接 `cil_from_container` フックを通してテストできる。

```
[Worker Node 1 (送信側)]                         [Worker Node 2 (受信側)]
+-----------------------------------+           +-----------------------------------+
| Client Pod (privileged: true)     |           | Server Pod                        |
|  xdperf (--xdp-mode generic)      |           |  xdperf-sink (または --tcp-server)|
|         │                         |           |         ▲                         |
|       eth0 (veth)                 |           |       eth0 (veth)                 |
+---------║-------------------------+           +---------║-------------------------+
          ║ veth ペア                                     ║ veth ペア
+---------║-------------------------+           +---------║-------------------------+
|       lxcXXX (※ GRO on が必須！) |           |       lxcYYY                      |
|         ▼                         |           |         ▲  │                      |
|  [cil_from_container] (往路計数)  |           |         │  ▼ [cil_from_container] |
|         │                         |           |  [cil_to_container]  (復路計数)   |
|         ▼ (Native Routing/VXLAN)  |           |         ▲                         |
|      物理 NIC / eth0 =============|===========|====> 物理 NIC / eth0              |
+-----------------------------------+           +-----------------------------------+
```

- **必須の 3 設定（忘れるとパケットが送出されない）**:
  1. **送信ノードのホスト側 `lxcXXX` で `ethtool -K lxcXXX gro on` を有効化する**: Cilium は既定でホスト側 `lxc*` の GRO を `off` にするが、Linux カーネルの `veth_xdp_xmit()` は対向に XDP も GRO も無い（`rq->napi == NULL`）と live-frame をすべて破棄する仕様のため、送信 Pod 対向の `lxcXXX` だけ `gro on` にする。
  2. **送信 Pod 内の `xdperf` に `--xdp-mode generic` を指定する**: Cilium は `lxc*` に TCX（`cil_from_container`）をアタッチしており XDP をアタッチしていないため、Pod 側で `native` にすると `veth_xdp_flush()` が対向 NAPI を起こせない。`--xdp-mode generic` なら `dev_queue_xmit()` 経由で確実に `cil_from_container` へ入る。
  3. **宛先に `ClusterIP`（Service）を使う場合は `socketLB.hostNamespaceOnly=true` にする**: 既定の Socket-LB は `connect()` syscall をフックするため、ソケットを使わない `xdperf` の SYN は未変換のまま出る。Pod 間直通は **Pod IP 直指定** でそのまま動作し、Service LB を通したい場合は `socketLB.hostNamespaceOnly=true` でパケット単位の Service 変換を有効化する。

#### (B) Cilium `bpf.datapathMode=netkit`（または `netkit-l2`）の場合
通常の Pod の `eth0` は `netkit`（`.ndo_xdp_xmit` 非対応）になるため、受信側は通常の Cilium `netkit` Pod とし、送信側は以下の **2A** または **2B** を選ぶ。

- **構成 2A（最高速・100G/400G 実機や別ノードからの負荷注入）**:
  - **送信 Pod を Worker Node 1 の `hostNetwork: true` Pod（または Cilium DRA / Multus で SR-IOV VF を渡した Pod）** にし、ノードの物理 NIC / VF（または `kind` ノードの `eth0`）から `--xdp-mode native` で送信する。
  - **受信 Pod は Worker Node 2 の通常の Cilium `netkit` Pod** とする。これにより受信ノードの物理 NIC（`cil_from_netdev` → `bpf_redirect_peer`）→ 受信 Pod `netkit` と、復路の `BPF_NETKIT_PEER`（`cil_from_container`）をフルレートで試験できる。
- **構成 2B（送信側・受信側の両方で Pod の `cil_from_container` を通す East-West 試験）**:
  - Cilium のノード別設定（`CiliumNodeConfig`）を用い、**送信用の Worker Node 1 を `datapath-mode: veth`**、**受信用（DUT）の Worker Node 2 を `datapath-mode: netkit`** に構成する：
    ```yaml
    apiVersion: cilium.io/v2
    kind: CiliumNodeConfig
    metadata:
      name: netkit-dut-node
      namespace: kube-system
    spec:
      nodeSelector:
        matchLabels:
          kubernetes.io/hostname: worker-node-2
      defaults:
        datapath-mode: netkit
    ```
  - これにより、送信 Pod（Worker Node 1）は通常の Pod として `veth` から `cil_from_container` を通って送信でき、受信 Pod（Worker Node 2）は本物の Cilium `netkit` Pod として受信・応答できる。

#### (C) Kubernetes + Cilium トポロジ選択早見表

| 測りたい対象 | 送信 Pod（`xdperf`）の置き方 | 受信 Pod（`xdperf-sink`）の置き方 | 必須のワンポイント設定 |
|---|---|---|---|
| **① Cilium 標準 (`veth`) の Pod 間通信 & プラグイン** | Worker 1 の通常 Pod (`veth`)<br>`--xdp-mode generic` | Worker 2 の通常 Pod (`veth`) | 送信ノードの `lxcXXX` で `ethtool -K lxcXXX gro on`（Service 経由なら `socketLB.hostNamespaceOnly=true`） |
| **② Cilium `netkit` モードの最大性能（100G/400G 実機含む）** | Worker 1 の **`hostNetwork: true` Pod**（または **DRA / SR-IOV VF Pod**）<br>`--xdp-mode native` | Worker 2 の通常 Pod (**`netkit`**) | 送信側は物理 NIC / VF から Native XDP で撃ち、Worker 2 の `netkit` Pod で受ける |
| **③ Cilium `netkit` モードで両端とも Pod `cil_from_container` を通す試験** | Worker 1（**`veth` ノード**）の通常 Pod<br>`--xdp-mode generic` | Worker 2（**`netkit` ノード**）の通常 Pod | `CiliumNodeConfig` で Worker 1 を `veth`、Worker 2 を `netkit` に分ける（Worker 1 の `lxcXXX` は `gro on`） |

---

### 3.4 マルチキュー `veth` スケーリング（UDP 301.5 Mpps / TCP 225.7 Gbps）と Kubernetes Pod（動的 `ethtool -L`・cgroup CPU 制限）の実測検証

#### (1) マルチキュー `veth` の線形スケーリング上限（64 vCPU Xeon 6746E, Linux `6.17.0-41-generic`）

`veth` のキュー数（`numtxqueues N numrxqueues N`）と `xdperf` の worker 数（`--parallelism N`）を `1 → 32` まで増やした際の単一ホスト `veth` ペアでの実測値：

| `veth` キュー数 / Worker 数 | 64B UDP (16,384 ポートスイープ, 対向 `--recv`) | ステートフル双方向 TCP (MSS 1448, 対向 `--tcp-server` XDP レスポンダ) | TCP 再送数 (`RTX`) |
|---:|---:|---:|---:|
| **1 キュー / 1 worker** | `8.43 Mpps` (`4.32 Gbps`) | `5.19 Gbps` (`0.45 M segs/s`, 16 フロー) | **0** |
| **4 キュー / 4 workers** | `37.18 Mpps` (`19.04 Gbps`) | `31.10 Gbps` (`2.69 M segs/s`, 64 フロー) | **0** |
| **8 キュー / 8 workers** | `79.59 Mpps` (`40.75 Gbps`) | `61.09 Gbps` (`5.27 M segs/s`, 128 フロー) | **0** |
| **16 キュー / 16 workers** | `153.43 Mpps` (`78.56 Gbps`) | `111.90 Gbps` (`9.66 M segs/s`, 256 フロー) | **0** |
| **24 キュー / 24 workers** | — | `169.73 Gbps` (`14.65 M segs/s`, 384 フロー) | **0** |
| **32 キュー / 32 workers** | **`301.50 Mpps`（毎秒 3 億 150 万 pkt, `154.37 Gbps`）** | **`225.69 Gbps`（`19.48 M segs/s`, 512 フロー）** | **0** |

#### (2) Kubernetes CNI が作成した既定 1 キュー `veth` を Pod 起動後に `ethtool -L` で動的マルチキュー化する検証

Cilium や Calico 等の CNI は、Pod 作成時に `veth` ペア（Pod 側 `eth0` ↔ ホスト側 `lxcXXX`）の有効キュー数（`real_num_tx_queues` / `real_num_rx_queues`）を **`1`** に初期化する。しかし Linux カーネルの `veth_newlink()`（`drivers/net/veth.c`）は作成時にホストの最大論理 CPU 数（`num_possible_cpus()`）分のキュー構造体を確保しているため、**Pod を再作成したり CNI を改造したりすることなく、稼働中の Pod の両端に `ethtool -L` を実行するだけで動的にマルチキュー化できる**。

```bash
# 1. Pod 側の eth0 を 16 キューに動的拡張
kubectl exec -it <pod-name> -- ethtool -L eth0 rx 16 tx 16

# 2. ホスト側の対向 lxcXXX を特定して 16 キューに動的拡張 (+ Cilium veth モードなら GRO on)
IFINDEX=$(kubectl exec <pod-name> -- cat /sys/class/net/eth0/iflink)
HOST_LXC=$(ip -o link | awk -F': ' -v idx="$IFINDEX" '$1 == idx {split($2, a, "@"); print a[1]}')
sudo ethtool -L "$HOST_LXC" rx 16 tx 16
sudo ethtool -K "$HOST_LXC" gro on
```

実際に `ip link add vtx type veth peer name vrx`（キュー数指定なし＝CNI 既定の 1 キュー状態）で作成した `veth` ペアに対して、16 worker（256 TCP フロー、3 秒間）で送信した比較実測値は以下のとおりである：

| 条件（同一の 1 キュー作成済み `veth` ペア） | Goodput (Gbps) | Data Segs/s | `xdp_xmit_errors` (リング溢れドロップ) | TCP 再送数 (`RTX`) | `warnVethQueues` 警告 |
|---|---:|---:|---:|---:|---|
| **1A: CNI 既定の 1 キューのまま送信 (`16w / 256f`)** | `8.79 Gbps` | `0.76 M segs/s` | `10,375` | `25,584` | `True` (警告出力) |
| **1B: 作成後に両端へ `ethtool -L <dev> rx 16 tx 16` を動的実行** | **`112.61 Gbps (+12.8x)`** | **`9.72 M segs/s`** | **`0`** | **`0`** | `False` |

#### (3) Kubernetes Pod で cgroup vCPU 制限（① CFS クォータ `cpu.max`、② コア固定 `cpuset.cpus`）が掛かっている場合の挙動と実測検証

Kubernetes Pod に CPU 制限（`resources.limits.cpu`）を設定している場合、cgroup の制限方式によって以下の **3 つの現象** が発生することを実機（cgroup v2 / `systemd-run --scope`）で検証した。

##### 検証 A：標準の CFS クォータ制限（`CPUQuota=200%` ＝ `limits.cpu: "2"`）で `--parallelism` を超過させた場合のスロットリング崩壊
`xdperf` の各 TX worker は 1 コアを 100% 消費するため、2 vCPU クォータ（100ms 周期あたり 200ms の CPU 時間）の cgroup 内で worker 数（`--parallelism`）を `2 → 8 → 16` に増やすと、100ms 周期の途中でクォータを使い果たして全 worker が CFS スケジューラにより強制凍結され、TCP の ACK 処理とウィンドウ進行がストールして性能が激減する：

| cgroup CFS クォータ設定 | `--parallelism` (Worker 数) | Goodput (Gbps) | Data Segs/s | `window_stalls` | 挙動 |
|---|---:|---:|---:|---:|---|
| `CPUQuota=200%` (`limits.cpu: "2"`) | **`2`（クォータ以下）** | **`24.04 Gbps`** | **`2.08 M segs/s`** | `9,791,318` | 凍結なしで連続送信 |
| `CPUQuota=200%` (`limits.cpu: "2"`) | `8`（クォータの 4 倍） | `2.78 Gbps (-88.4%)` | `0.24 M segs/s` | `17,287,522` | 周期ごとに 75ms 凍結し約 1/9 に激減 |
| `CPUQuota=200%` (`limits.cpu: "2"`) | `16`（クォータの 8 倍） | `1.49 Gbps (-93.8%)` | `0.13 M segs/s` | `21,577,179` | 周期ごとに 87.5ms 凍結し約 1/16 に激減 |

* **対策**: CFS クォータ環境では、必ず **`--parallelism <= limits.cpu`** に設定する。

##### 検証 B：`cpuset.cpus` コア固定（Kubernetes CPU Manager `static` ポリシー、例：`AllowedCPUs=2,6,10,14` の 4 コア割り当て）における 2 つの罠
1. **既定 `--cpu-mode auto` での `SchedSetaffinity` エラー（`EINVAL`）**:
   - `AllowedCPUs=2,6,10,14` に制限された cgroup 内で既定の `--cpu-mode auto --parallelism 4` を実行すると、ホスト全体の `/sys/devices/system/node/node*/cpulist` から `CPU 0,1,2,3` を選んで `SchedSetaffinity` を呼ぶため、以下のとおり `invalid argument (EINVAL)` で即座に失敗する：
     ```text
     xdperf client start failed: worker failed: failed to set CPU affinity: invalid argument
     ```
   - **対策**: `cpuset` 制限下の Pod では、`--cpu-mode 2,6,10,14`（`/sys/fs/cgroup/cpuset.cpus.effective` の値）を明示指定する。
2. **`veth_xdp_xmit()` のキュー選択式 `cpu % peer_rx_queues` による「剰余衝突（Modulo Collision）」の罠**:
   - カーネルの `veth_xdp_xmit()` は、対向（`vrx` / `lxcXXX`）のどの RX キュー（`xdp_ring`）にフレームを入れるかを **`送信元の物理 CPU 番号 % 対向の有効 RX キュー数`** で決定する。
   - もし Pod に飛び飛びの 4 コア **`CPU 2, 6, 10, 14`** が割り当てられた状態で、4 worker に合わせて **`ethtool -L vrx rx 4 tx 4`（4 キュー）** に設定すると、`2%4 = 6%4 = 10%4 = 14%4 = 2` となり、**4 worker 全員のパケットが `rx_queue_2` の単一 `xdp_ring`（256 エントリ）に 100% 集中してリング溢れと大量再送を引き起こす**。
   - ここで対向のキュー数を **`ethtool -L vrx rx 16 tx 16`（16 キュー：最大 CPU 番号 $14 + 1$ 以上）** に増やすと、`cpu % 16` が `2, 6, 10, 14` の 4 つの独立キューに完璧に分散し、ドロップと再送がゼロになって性能が **3.92 倍** に回復する：

| `AllowedCPUs=2,6,10,14` (`--cpu-mode 2,6,10,14`, 4w/64f) | 対向 `ethtool -L` キュー数 | Goodput (Gbps) | `xdp_xmit_errors` | TCP 再送数 (`RTX`) | 対向 `ethtool -S vrx` のキュー別受信パケット実測内訳 |
|---|---:|---:|---:|---:|---|
| **3B: worker 数と同じ 4 キュー (`cpu % 4 == 2` で全員衝突)** | `rx 4 tx 4` | `8.27 Gbps` | `1,936` | `6,713` | **`rx_queue_2: 2,146,911`** (`rx_queue_0: 3`, `rx_queue_1: 2`, `rx_queue_3: 0`) |
| **3C: 剰余が衝突しない 16 キュー (`cpu % 16 = 2,6,10,14`)** | **`rx 16 tx 16`** | **`32.41 Gbps (+3.92x)`** | **`0`** | **`0`** | **`rx_queue_2: 2,125,632` / `rx_queue_6: 2,079,424` / `rx_queue_10: 2,107,328` / `rx_queue_14: 2,082,898`** |

* **対策**: `cpuset` で非連続な CPU 番号 $c_1, \dots, c_W$ が割り当てられている場合は、必ず **$c_i \bmod Q$ がすべて異なるキュー数 $Q$（最も確実なのは最大 CPU 番号 $\max(c_i) + 1$ 以上）** を `ethtool -L` で設定する。


