# 設計: XDP TCP ストリームモード (`--tcp`)

ステータス: M1/M2 実装済み (veth で IPv4 / IPv6 / VLAN の各ケースが通る、`examples/tcpstream`)。XDP レスポンダ (`--tcp-server`、12 節) 実装済み。コードレビュー (OCR round 1) の指摘対応を 13 節に記載。実機 100G での検証 (M3) は未実施。
使い方は [tcp_stream.md](tcp_stream.md)。

## 1. 目的と範囲

iperf3 のように、**実在する Linux の TCP スタック (任意の TCP シンク) を相手に** 複数の TCP コネクションを張り、
一方向にデータを流し、FIN で閉じるまでをすべて XDP (BPF_PROG_RUN live frames + XDP_TX) で行う。
カーネルの TCP ソケットは一切使わない。

得たい指標:

- 確立したコネクション数、完了 (FIN 完了) したコネクション数、失敗数 (RST / SYN タイムアウト)
- ACK 済みバイト数から算出する goodput (bps)、送信セグメント数、再送回数
- 既存の TX/RX 統計との並記 (pps、Mbps)

### スコープ (最初のスパイク)

| 項目 | 範囲 |
|---|---|
| L3 | IPv4 と IPv6 (フローごとではなく実行ごとにどちらか一方) |
| L2 | Ethernet、任意で 802.1Q シングルタグ (`--tcp-vlan-id`)。QinQ は対象外 |
| 方向 | クライアント→サーバの一方向データ。サーバからのデータは ACK するだけで捨てる |
| 制御 | 固定ウィンドウ (飛行中セグメント数 N と相手の受信ウィンドウの小さい方)。輻輳制御なし |
| 再送 | RTO タイムアウトと重複 ACK 3 回。再送は `snd_una` からの go-back-N |
| オプション | SYN で MSS と Window Scale を送る。受信側は SYN-ACK の Window Scale だけ解釈する。SACK と Timestamps は使わない |
| ペイロード | 全ゼロ (チェックサム計算を O(1) にするため。後述) |
| 相手 | 標準の Linux TCP スタック上の任意のシンク (`socat`, 付属の `xdperf-sink`, iperf3 ではない)、または XDP レスポンダ `xdperf run --tcp-server` (12 節) |
| デバイス | `--device` 1 枚に TX (live frames) と RX (XDP attach) を同居させる。`--rx-device` 分離は対象外 |
| 次ホップ解決 | IPv4 は ARP、IPv6 は NDP。いずれもカーネルの近隣キャッシュを netlink で引く (既存 `pkg/plugin` の実装を再利用) |

### 非目標 (今回やらない)

QinQ、SACK、動的ウィンドウ/輻輳制御、双方向データ、keep-alive 上の複数リクエスト、
iperf3 制御プロトコル互換、プラグイン (WASM) からの TCP テンプレート定義、`--rx-device` 分離。
これらは後続で検討する。特に「クローズ後に新しいポートで再接続し続ける」モード (接続レート測定) は、
本設計の状態機械にそのまま足せるので第 2 段階とする。

## 2. 全体構造

```
Go (pkg/xdperf/tcp.go)
  ├── テンプレートフレーム生成 (Eth/IPv4 または IPv6/TCP + ゼロペイロード mss バイト)
  ├── tcp_cfg_map / tcp_flow_map / tcp_cpu_state_map 初期化
  ├── xdp_rx_tcp を --device に attach
  ├── worker CPU ごとに bpf_prog_run(xdp_tx_tcp, live frames) をループ
  └── 統計表示、完了判定、drain (FIN 送出) 指示

XDP
  ├── xdp_tx_tcp : live frames で 1 回呼ばれるごとに「自 CPU が担当するフロー」を 1 つ選び、
  │               状態に応じて SYN / データ / FIN / 再送 のいずれかを組み立てて XDP_TX。
  │               送るものが無ければ XDP_DROP (フレームは送られない)。
  └── xdp_rx_tcp : 実験フローに属する受信パケットだけを処理し、フロー状態を更新。
                   応答 (ACK) が必要なら受信フレームを書き換えて XDP_TX、不要なら XDP_DROP。
                   実験フロー以外は XDP_PASS (他の通信に影響しない)。
```

設計上の要点は次の 3 つ。

1. **タイマーを持たない。** クライアントの動作はすべて「TX ループの 1 イテレーション」か「受信パケット 1 つ」を契機にする。
   タイムアウト判定は TX ループ側が `bpf_ktime_get_ns()` と `last_send_ns` の差で行う。
2. **カーネル TCP スタックに実験パケットを見せない。** `xdp_rx_tcp` は実験フローの受信パケットを必ず TX か DROP で消費する。
   PASS するとソケットの無いカーネルが RST を返してサーバ側コネクションを壊す。
3. **フロー状態は共有 ARRAY マップに置き、`bpf_spin_lock` で TX/RX 間の更新を直列化する。**
   ロック区間では状態の読み書きだけを行い、パケット操作ヘルパはロック解放後に呼ぶ。

## 3. データ構造 (src/xdp_tcp.h)

```c
#define MAX_TCP_FLOWS 65536

enum tcp_flow_state {
    TF_CLOSED = 0,     // 未接続 (SYN 未送出)
    TF_SYN_SENT,
    TF_ESTABLISHED,
    TF_FIN_WAIT_1,     // 自分の FIN 送出済み、ACK 待ち
    TF_FIN_WAIT_2,     // 自分の FIN は ACK 済み、相手の FIN 待ち
    TF_DONE,           // 正常終了 (相手 FIN を ACK した)
    TF_FAILED,         // RST 受信、または SYN/FIN の再送上限超過
};

struct tcp_flow {
    struct bpf_spin_lock lock;
    __u8  state;
    __u8  syn_retries;
    __u8  dup_acks;
    __u8  rtx_pending;      // RX が重複 ACK 3 回を検出 → TX が snd_una から再送
    __u8  peer_fin;         // 相手の FIN を受信済み
    __u8  wscale;           // 相手が SYN-ACK で提示した window scale
    __u16 src_port;
    __u32 iss;              // 自分の ISN
    __u32 snd_una;          // 未 ACK の最小 seq
    __u32 snd_nxt;          // 次に送る seq
    __u32 rcv_nxt;          // 次に期待する相手 seq (= 自分が送る ack 番号)
    __u32 snd_wnd;          // 相手の受信ウィンドウ (scale 適用後、バイト)
    __u64 bytes_target;     // このフローで送るバイト数 (0 = 無制限、drain まで)
    __u64 bytes_acked;
    __u64 last_send_ns;     // 最後に新規/再送セグメントを送った時刻 (RTO 判定用)
    __u64 last_ack_ns;
};

struct tcp_cfg {
    __u32 flow_count;
    __u32 window_segs;      // 飛行中セグメント数の上限
    __u16 mss;              // セグメントのペイロード長
    __u16 port_base;        // src port = port_base + flow_idx
    __u16 dst_port;
    __u16 hdr_len;          // Eth(+VLAN) + IP + TCP(20): 54/74、VLAN 付きなら +4
    __u16 l3_off, l4_off;   // l3_off = 14 (VLAN 付き 18)、l4_off = l3_off + 20 (IPv4) / 40 (IPv6)
    __u16 vlan_tci;         // 0 = タグ無し。非 0 なら RX でも TCI の VID が一致するものだけ扱う
    __u8  ip_version;       // 4 or 6
    __u8  src_ip[16], dst_ip[16]; // network byte order。IPv4 は先頭 4 バイト
    __u64 bytes_per_flow;   // 0 = 無制限
    __u64 rto_ns;           // 再送タイムアウト
    __u8  max_syn_retries;
    __u8  drain;            // 1 = 新規データを止めて FIN を送る (Go が duration 終了時に立てる)
};

struct tcp_cpu_state {   // PERCPU_ARRAY(1)。Go が worker CPU ごとに書く
    __u32 first;          // この CPU が担当する最初のフロー index
    __u32 stride;         // = parallelism (フローは CPU 間でインターリーブ)
    __u32 count;          // この CPU が担当するフロー数
    __u32 cursor;         // ラウンドロビン位置
};

struct tcp_stats {       // PERCPU_ARRAY(1)
    __u64 syn_sent, synack_rcvd, established;
    __u64 data_segs, data_bytes, bytes_acked;
    __u64 rtx_segs, rtx_timeouts, rtx_dupack;
    __u64 fin_sent, done, failed, rst_rcvd;
    __u64 acks_rcvd, idle_iters, window_stalls, unexpected;
};
```

マップ: `tcp_flow_map` (ARRAY, MAX_TCP_FLOWS)、`tcp_cfg_map` (ARRAY, 1)、
`tcp_cpu_state_map` (PERCPU_ARRAY, 1)、`tcp_stats_map` (PERCPU_ARRAY, 1)。
`bpf_spin_lock` は PERCPU マップに置けないので `tcp_flow_map` は通常の ARRAY にする。
`tcp_flow` は 1 エントリ約 80B、65536 フローで約 5MB。

フローの担当 CPU: `flow_idx = first + cursor * stride`。parallelism が P なら CPU スロット k は
`k, k+P, k+2P, ...` を担当する。フローの所有権は TX 側だけにあり、RX は NAPI が動く任意の CPU で
ロックを取って更新する。

## 4. 送信プログラム `xdp_tx_tcp`

live frames の入力フレーム (Go が作る) は `hdr_len + mss` バイトの完全なフレーム。
MAC、IP アドレス、宛先ポート、TTL 等はテンプレートの値をそのまま使い、以下のフィールドだけ毎回書く。

| 書くフィールド | 理由 |
|---|---|
| TCP src port, seq, ack, flags, doff, window, checksum | フローと状態で変わる |
| TCP オプション領域 (l4_off+20 .. +27) | SYN では MSS+NOP+WS、それ以外ではゼロ (後述の「バッファ再利用」のため明示的に消す) |
| IPv4: total length, id, header checksum | 長さが変わる |
| IPv6: payload length | 長さが変わる。IPv6 ヘッダにチェックサムは無い |

手順:

1. `tcp_cfg`、`tcp_cpu_state`、`tcp_stats` を取得。
2. 担当フローを最大 `TX_SCAN` (8) 個まで順に見て、送るものがある最初のフローを選ぶ。全部送るものが無ければ `idle_iters++` して XDP_DROP。
3. フローをロックして動作を決め、状態を更新し、送信に必要な値 (seq, ack, flags, len) をスタックにコピーしてアンロック。

   | 状態 | 条件 | 動作 |
   |---|---|---|
   | CLOSED | drain でない | SYN を送る。`iss` は flow_idx と起動時乱数から決める。state=SYN_SENT |
   | SYN_SENT | now - last_send > rto | SYN 再送。`syn_retries++`、上限超過で FAILED |
   | ESTABLISHED | `rtx_pending` または (snd_una != snd_nxt かつ now - last_send > rto) | `snd_nxt = snd_una` にして再送 (go-back-N の先頭セグメント)。`rtx_segs++` |
   | ESTABLISHED | 残りバイトあり かつ in_flight + len <= min(window_segs*mss, snd_wnd) | データセグメント。len = min(mss, 残り)。`snd_nxt += len` |
   | ESTABLISHED | 残りバイト無し (または drain) かつ snd_una == snd_nxt | FIN+ACK。`snd_nxt += 1`、state=FIN_WAIT_1 |
   | FIN_WAIT_1 | now - last_send > rto | FIN 再送 |
   | それ以外 | | 何もしない (次のフローへ) |

4. `bpf_xdp_adjust_tail` でフレーム長を `hdr_len + len` (+ SYN ならオプション 8B) に合わせる。
5. ヘッダフィールドを `bpf_xdp_store_bytes` で書く。
6. チェックサム:
   - IPv4 ヘッダ: 20B をアンロールして加算 (`bpf_loop` 不要)。IPv6 では不要。
   - TCP: 擬似ヘッダ (IPv4: 12B、IPv6: 40B) + TCP ヘッダ 20B (+ オプション 8B) をアンロールして加算。**ペイロードは全ゼロなので寄与 0**。
     擬似ヘッダのアドレス部分は実行中不変なので、Go 側で事前計算した部分和を `tcp_cfg.pseudo_sum` に置き、BPF ではポート/長さ/ヘッダだけ加算する。
     これにより既存の `xdp_tx` が持つ「初回フル計算→キャッシュ」の仕組みが不要になり、全セグメントを O(1) で組み立てられる。
7. 統計を更新して XDP_TX。

### ペイロードをゼロにする理由と、バッファ再利用の注意

live frames はフレームプールを再利用するため、前のイテレーションで書いた内容が残る (既存 `xdp_tx` がベースパケットを毎回コピーし直すのはこのため)。
一方 `bpf_xdp_adjust_tail` は伸長時に新しい末尾をゼロ埋めする。したがって

- ペイロード領域 (l4_off+28 以降) は「テンプレート時点でゼロ」かつ「以降一度も非ゼロを書かない」ので常にゼロ。
- l4_off+20 .. +27 だけは SYN のオプションを書くため、データ/FIN セグメントでは明示的にゼロで上書きする。

ペイロードにパターンを入れたい場合は、Go 側でペイロードの 16bit 語の prefix sum テーブルをマップに置けば
同じ O(1) で対応できる (将来の拡張)。

## 5. 受信プログラム `xdp_rx_tcp`

`--tcp` 時は `xdp_pass_dummy` の代わりにこれを `--device` に attach する。

1. `cfg.vlan_tci` が非 0 なら 802.1Q タグがあり VID が一致すること、0 ならタグが無いこと。その上で Eth の次が `cfg.ip_version` と一致する IPv4/IPv6 で、かつ上位が TCP でなければ XDP_PASS。IPv6 は拡張ヘッダ無し (next header が直接 TCP) の場合だけ扱う。
   カーネル自身が出す IPv6 の NS/NA/RS などはここで PASS されるので、NDP はカーネルに任せられる。
2. `daddr == cfg.src_ip && saddr == cfg.dst_ip && sport == cfg.dst_port && port_base <= dport < port_base + flow_count` でなければ XDP_PASS。
   (これが Cilium 測定で必要だった「対象外トラフィックを変更せず通す受信フィルタ」そのものになる。)
3. `flow = tcp_flow_map[dport - port_base]`。flags、seq、ack、window、payload_len (IPv4: tot_len - ihl*4 - doff*4、IPv6: payload_len - doff*4) を読む。
   SYN-ACK のときだけオプションを走査して Window Scale を取る (上限 40B、有界ループ)。
4. ロックして状態遷移:

   | 状態 | 受信 | 処理 | 応答 |
   |---|---|---|---|
   | 任意 | RST | state=FAILED、`rst_rcvd++` | なし |
   | SYN_SENT | SYN+ACK, ack == iss+1 | rcv_nxt=seq+1、snd_una=iss+1、snd_wnd=win (SYN-ACK の窓はスケールしない、RFC 7323)、state=ESTABLISHED | ACK |
   | ESTABLISHED / FIN_WAIT_1 | ACK, snd_una < ack <= snd_nxt | snd_una=ack、bytes_acked 加算、dup_acks=0、snd_wnd 更新 | (データ/FIN が無ければ) なし |
   | ESTABLISHED | ACK, ack == snd_una, payload 0, SYN/FIN なし | dup_acks++。3 で `rtx_pending=1`、`rtx_dupack++` | なし |
   | ESTABLISHED / FIN_WAIT_x | payload > 0 | rcv_nxt += payload (データは捨てる) | ACK |
   | ESTABLISHED / FIN_WAIT_x | FIN | rcv_nxt += 1、peer_fin=1 | ACK |
   | FIN_WAIT_1 | ack == snd_nxt (自分の FIN が ACK された) | state = peer_fin ? DONE : FIN_WAIT_2 | |
   | FIN_WAIT_2 | FIN | state=DONE、`done++` | ACK |
   | その他 | | `unexpected++` | なし |

   seq 比較は `(s32)(a - b)` で行う (wrap 対応)。
5. アンロック。応答が必要なら受信フレームをその場で ACK に書き換える:
   MAC/IP/ポートを入れ替え、seq=snd_nxt、ack=rcv_nxt、flags=ACK、doff=5、`adjust_tail` で `hdr_len` に切り詰め、
   IP 長フィールドと IPv4 ヘッダ/TCP チェックサムを (ヘッダのみ) 再計算して XDP_TX。不要なら XDP_DROP。

TIME_WAIT は持たない。DONE になったフローのポートに遅延パケットが来ても DROP するだけで害はない。

## 6. Go 側 (pkg/xdperf/tcp.go)

### CLI フラグ

| フラグ | 既定 | 意味 |
|---|---|---|
| `--tcp` | off | TCP ストリームモード。プラグイン不要 |
| `--tcp-dst ip:port` | 必須 | 接続先。`[2001:db8::2]:5201` の形で IPv6 も指定できる。アドレスファミリはここで決まる |
| `--tcp-src-ip` | デバイスの同ファミリの先頭グローバルアドレス | 送信元 IP。デバイスに付いている必要がある (ARP/NDP 応答はカーネルに任せる) |
| `--tcp-flows` | parallelism | 同時コネクション数 (<= 65536) |
| `--tcp-port-base` | 10000 | 送信元ポートの先頭。`port_base + flows <= 65536` (13 節で 40000 から変更) |
| `--tcp-window` | 32 | 飛行中セグメント数上限 (フローごと) |
| `--tcp-mss` | 1448 (IPv4) / 1428 (IPv6) | セグメントのペイロード長。フレーム長 hdr_len+mss <= MTU+14 かつ <= MAX_PACKET_SIZE |
| `--tcp-bytes` | 0 | フローごとの送信バイト数。0 なら `--duration` まで流して drain |
| `--tcp-rto` | 200ms | 再送タイムアウト |
| `--tcp-vlan-id` / `--tcp-vlan-pcp` | 0 / 0 | 802.1Q タグ。vlan-id が 0 ならタグ無し。既存 UDP プラグインの `vlan_id`/`vlan_pcp` と同じ意味 |

既存フラグの扱い: `--parallelism` は worker CPU 数 (フローを分配)。`--duration` は終了時刻 (0 なら全フロー DONE まで)。
`--pps` はイテレーション数の上限 (= セグメント送出レートの上限) として既存の ticker ループを使う。
`--count`、`--plugin*`、`--infinite` は `--tcp` と併用不可 (Validate で弾く)。

### 処理の流れ

1. テンプレートフレーム生成: gopacket で Eth(src=デバイス MAC, dst=ネクストホップ MAC)[/Dot1Q]/IPv4(DF, ttl 64) または IPv6(hop limit 64)/TCP(win 65535)/ゼロペイロード。
   VLAN 指定時は、ネクストホップ解決を `--device` 上の VLAN サブインターフェース (あれば) で行い、フレームは親デバイスからタグ付きで送る。受信 ACK の書き換えはタグをそのまま残す。
   ネクストホップは netlink の route lookup で引き、MAC は `pkg/plugin` の `resolveNeighbor`/`lookupNeighborCache` (IPv4/IPv6 両対応) を再利用して解決する。
2. マップ初期化: `tcp_cfg`、`tcp_flow_map[0..flows)` (state=CLOSED, src_port, bytes_target)、worker CPU ごとの `tcp_cpu_state`。
3. `xdp_rx_tcp` を attach (既存 `attachXDP`)。
4. worker ごとに `run()` と同じループで `xdp_tx_tcp` を `bpf_prog_run` する。
   `Repeat` は `--batch-size` 相当、`Data` はテンプレート、`BPF_F_TEST_XDP_LIVE_FRAMES`。
5. 監視 goroutine: 1 秒ごとに `tcp_stats_map` を集計して表示。`done + failed == flows` で ctx をキャンセル。
   `--duration` 到達で `cfg.drain=1` を書き、最大 `2*rto` 待って FIN が返るのを待ってから終了。
6. 終了時サマリ: 確立/完了/失敗数、ACK 済みバイト、goodput Gbps、再送数、セグメント数、平均フレーム長。

### 表示例

```
tcp: est 100/100 done 0 fail 0 | 2.41 Gbps acked, 208,113 segs/s, rtx 0/s
```

## 7. テストと検証 (examples/tcpstream)

veth + netns の既存基盤 (`examples/common`) を使う。

```
ns xdperf-tx (xdp-tx 192.168.100.1)  <-veth->  ns xdperf-rx (xdp-rx 192.168.100.2)
   xdperf run --tcp --device xdp-tx ...            xdperf-sink --tcp :5201   (カーネル TCP で受けてバイト数を数える)
```

- `cmd/xdperf-sink`: TCP (と後で UDP) を受けてコネクション数・受信バイト数を数える小さな Go プログラム。
  Cilium 測定のバックエンド Pod にもそのまま使う前提で作る。
- IPv4 と IPv6 の両方、さらに VLAN タグ付き (受信 ns 側に VLAN サブインターフェースを作る、`simpleudp-vlan` と同じ構成) を回す (veth に両ファミリのアドレスを付ける。IPv6 のカーネル自発パケットは `xdp_rx_tcp` が PASS するので計数に影響しない)。
- 合格条件 (test.sh): フロー数 F、`--tcp-bytes` B として、
  xdperf 側 `done == F`、`bytes_acked == F*B`、シンク側 `connections == F`、`bytes == F*B`、再送 0。
- 受信側の XDP_TX 経路のために、既存の UDP シナリオと同じく受信 ns 側にも NAPI が必要 (シンク側 veth に GRO on か dummy attach)。
  `examples/simpleudp-no-rx-attach` の知見を流用する。

veth で通ったら、実機 100G (E810) での確認はご本人の環境で行う。見るべき点は、
XDP_TX の戻り経路が native で動くこと、RX の NAPI と TX worker の CPU 競合、`--tcp-window` と RTT による 1 フロー上限。

## 8. カーネル要件と verifier 上の注意

- live frames (5.18+)、`bpf_xdp_load_bytes/store_bytes` (5.18+)、`bpf_spin_lock` (5.1+)、`bpf_loop` は使わない。
- ロック区間で helper を呼ばない。状態をスタックにコピーしてから組み立てる。
- オプション走査は固定回数 (最大 10 回) の有界ループ。
- パケット書き換えは全て `bpf_xdp_store_bytes` の定数長呼び出し (既存 `apply_diff` と同じ方針、6.1 系の verifier 対策)。
- `xdp_rx_tcp` は既存 `xdp_rx` とは別プログラムにし、既存の UDP 経路の verifier 負荷を変えない。

## 9. 段階

| 段階 | 内容 | 完了条件 |
|---|---|---|
| M1 | 状態機械、TX/RX プログラム、Go 配線、シンク | veth で F フロー × B バイトが完走し、両側の数が一致する |
| M2 | 再送 (RTO/重複 ACK)、drain、統計表示、examples/tcpstream、docs | `make examples` に組み込まれて通る。再送を人為的に起こして回復する |
| M3 | 実機 100G 検証 (ご本人)、CPU 競合と window 調整 | 片方向 TCP の Gbps を既存 UDP ベンチと同じ表で出せる |
| M2.5 | XDP レスポンダ `--tcp-server` (12 節) | veth で `--tcp` と Linux クライアント (socat) の両方から受けて数が一致する |
| 第 2 段階 | クローズ後に再接続する接続レートモード、`--rx-device` 分離、QinQ、IPv6 拡張ヘッダ | 別設計で扱う |

## 10. 実装で分かったこと (veth 検証時)

| 事象 | 原因 | 対処 |
|---|---|---|
| 最後のフローの最終 ACK だけが相手に届かず、相手が LAST-ACK で残る | veth の `veth_xdp_flush` は、対向に XDP プログラムが無いと XDP_TX したフレームを積んだ ring の NAPI を起こさない (GRO で NAPI があっても)。後続トラフィックが無い最終 ACK だけ ring に残る | veth では対向にも XDP プログラムを付ける (`xdperf-sink -xdp-pass-dev`)。加えて、最後のフローが閉じたあと `2*rto` の linger を入れ、DONE 状態でも再送 FIN に ACK を返す。実 NIC では起きない |
| VLAN 指定時に SYN-ACK がカーネルに PASS され RST される | 対向カーネルは 802.1Q を hwaccel (skb メタデータ) で付けるため XDP からはタグ無しに見える。実 NIC の rx-vlan-offload でも同じ | VLAN 指定時はタグ無しフレームも受け付け、返す ACK には `bpf_xdp_adjust_head` でタグを押し戻す |
| VLAN 指定時に約 3 割のデータセグメントが壊れて届く (ethertype 不正) | live frames のフレームは再利用され、同一ホストの受信側 (veth) はそのページ上に skb を作って `skb_vlan_untag` が MAC ヘッダを 4 バイト memmove する。TX 側は IP/TCP ヘッダしか書き直していなかった | TX は毎回 L2+IP ヘッダを `tcp_cfg.hdr_tmpl` から書き直す。フレームの残骸に一切依存しない |
| `bpf_prog_run` の戻り値が常に 0 | live frames モードはプログラムのアクションを返さない | 既存クライアントと同じく 0 を成功とみなす |
| 1000 フロー同時で再送の嵐、一部フローが失敗 | veth の xdp_ring (256) がバーストで溢れ、go-back-N がロスを増幅。SYN/FIN の固定 RTO 5 回では足りない | 重複 ACK 3 回は先頭セグメントのみ再送 (巻き戻さない)、RTO 時だけ go-back-N。SYN/FIN 再送は指数バックオフ 6 回 |
| `store_zero_small` の switch が verifier に拒否される | clang が各 case を可変長の 1 呼び出しにまとめ、長さが定数でなくなる | 短いセグメントは「いったん伸ばして 8 バイトをゼロ化してから縮める」方式にし、可変長の store を無くした |

## 11. 未決事項

- ISN の決め方: 起動時乱数 + flow_idx * 定数 で十分か (同じポートの再利用は第 2 段階まで無い)。
- `--pps` の意味を「イテレーション上限」とするか、bps 指定を別に設けるか。
- drain 時に相手が FIN を返さない場合の打ち切り時間 (現状は `127*rto + 1s`、FIN 再送バックオフ 1+2+...+64 の合計をカバー。超えたら RST で abort。13 節)。
- 送信元 IP をデバイスに付けない運用 (ARP を XDP で応答) を将来やるか。Cilium 測定では送信専用ホストなので当面は不要。

## 12. XDP レスポンダ `--tcp-server`

### 12.1 目的

`--recv --swap-resp` (UDP エコー) の TCP 版。受信側でもカーネル TCP を使わず、XDP だけで
SYN に SYN-ACK を返し、データを捨てて ACK を返し、FIN に FIN で応える。これで

- DUT (Cilium の NodePort 等) を挟んで **両端を xdperf にする** 構成が取れる。受信側カーネル TCP の処理能力が
  ボトルネックにならないので、経路そのものの TCP 容量を測れる。
- `xdperf-sink` (カーネル TCP) と差し替えて同じ表に並べれば、「経路の限界」と「バックエンド TCP スタックの限界」を切り分けられる。

DPDK 系のステートフル負荷ツール (TRex ASTF、WARP17、dperf) はいずれもサーバ側もツール自身がエミュレートしており、
本節は dperf のサーバ側 (SYN→SYN-ACK、データ→ACK、FIN→FIN+ACK、TIME_WAIT の即時再利用) を XDP に写したものに相当する。
相手は `--tcp` クライアントでも、一方向に送って閉じる普通の Linux TCP クライアント (socat、nc) でもよい。応答を待つクライアント (iperf3 -c、curl) は使えない。

### 12.2 範囲

| 項目 | 範囲 |
|---|---|
| L3 / L2 | クライアントと同じ (IPv4 または IPv6、任意で 802.1Q)。受信側 NIC の rx-vlan-offload / veth hwaccel でタグが剥がれたフレームも受け付け、返信にタグを押し戻す |
| 待ち受け | `--tcp-listen [ip]:port` の 1 ポート。IP を省略 (`:5201`) すると IPv4 の全アドレス、`[::]:5201` で IPv6 の全アドレス。`--tcp-listen 10.0.0.2:5201` のように指定すれば宛先アドレスも一致条件に入る |
| 方向 | クライアント→サーバの一方向データ。受けたデータは捨てる。サーバからデータは送らない (固定レスポンス送信は将来) |
| ACK | 既定は 1 セグメントごとに ACK (`--tcp-ack-every 1`)。N を指定すると N セグメントごと。PSH / FIN 付き、順序外、重複セグメントには即 ACK |
| ウィンドウ | SYN-ACK / ACK で常に 65535 を広告。クライアントが SYN で Window Scale を提示していれば WS=7 (約 8MB) を返す。データは捨てるので実質無制限 |
| オプション | SYN-ACK に MSS と (提示があれば) Window Scale。SACK / Timestamps は返さないので、Linux クライアントはそれらを無効にして動く |
| 再送 | 自前のタイマーを持たない。SYN-ACK と FIN+ACK の再送は「相手が再送してきた SYN / FIN に応答する」形で行う (dperf と同じ reactive 方式) |
| 状態の寿命 | LRU_HASH。Go 側のスイーパが 1 秒ごとに表を舐め、`--tcp-sweep-after` (既定 `max(65 * rto, 2s)`、13 節) より古い LAST_ACK (最終 ACK がロスした) は「閉じた」と数えて削除、同じく古い SYN_RCVD (半開き) は `syn_timeouts` として削除する。それ以外の滞留は LRU 追い出しか、同じ (IP, ポート) からの新しい SYN での再利用で消える。TIME_WAIT は持たない |
| CPU | attach のみ (worker 不要)。処理は NIC の RSS が振った CPU で行う |

### 12.3 データ構造 (src/xdp_tcp_server.h)

```c
struct tcp_srv_key {            // (相手の IP, 相手のポート, 自分の IP)。IPv4 は [0] のみ
    __u32 addr[4];
    __u32 local[4];             // 待ち受けがワイルドカードでも宛先 IP ごとに別フロー
    __u16 port;
    __u16 pad;
};

enum tcp_srv_state { TS_SYN_RCVD = 1, TS_ESTABLISHED, TS_LAST_ACK };

struct tcp_srv_flow {
    __u8  state;
    __u8  wscale_ok;      // クライアントが SYN で WS を提示した
    __u16 unacked_segs;   // 最後に ACK を返してから受けたデータセグメント数 (ack_every 用)
    __u32 iss, snd_nxt, rcv_nxt;
    __u64 bytes_rcvd;
    __u64 last_ns;
};

struct tcp_srv_cfg {
    __u16 listen_port, vlan_id;
    __u8  vlan_pcp, ip_version, ack_every, any_addr;
    __u16 mss;            // SYN-ACK で広告する MSS
    __u32 listen_ip[4];
};

struct tcp_srv_stats {  // PERCPU
    __u64 syn_rcvd, synack_sent, accepted, data_segs, bytes_rcvd, acks_sent, dup_acks_sent, out_of_order,
          fin_rcvd, fin_sent, closed, rst_rcvd, recycled, table_full, stray, unexpected, build_errors,
          rst_sent, reset_est, recycled_est, bad_len;
};
```

マップ: `tcp_srv_flow_map` (LRU_HASH、`--tcp-max-conns`、既定 262144。`--tcp-server` 以外のモードでは 1 に縮める)、
`tcp_srv_cfg_map` (ARRAY 1)、`tcp_srv_stats_map` (PERCPU_ARRAY 1)。

クライアント側 (`tcp_flow_map`) と違い **spin lock を持たない**。1 フローのパケットは NIC の RSS (veth では送信 CPU) で
同じ CPU に届くので、同一フローの更新は実際には直列化されている。`bpf_spin_lock` は LRU_HASH に置けないため、
LRU による自動掃除を優先した。RSS が同一フローを複数キューに散らす異常系では統計が僅かにずれ得るが、
データを捨てるレスポンダなので致命的ではない。

### 12.4 受信プログラム `xdp_rx_tcp_server`

1. L2/L3/L4 のフィルタはクライアント RX と同じ方針。VLAN、IP バージョン、(any_addr でなければ) 宛先 IP、TCP、
   `dport == listen_port` のどれかが外れたら XDP_PASS。ここを通ったパケットは絶対に PASS しない。
2. IP の申告長 (IPv4 `tot_len` / IPv6 `payload_len`) がフレームに収まり、TCP ヘッダ長 (`doff`) が IP の申告長に収まることを
   確認する。外れたら状態を変えずに DROP (`bad_len++`)。フレーム末尾の Ethernet パディングは許す。
3. キー = (saddr, sport, daddr) で `tcp_srv_flow_map` を引く。

   | 受信 | エントリ | 処理 | 応答 |
   |---|---|---|---|
   | RST, `seq == rcv_nxt` | あり | 削除、`rst_rcvd++` | なし |
   | RST, `seq != rcv_nxt` | あり | RFC 5961 3.2。SYN_RCVD なら捨てる | challenge ACK (確立済み・LAST_ACK) |
   | SYN (ACK なし) | なし | 作成: SYN_RCVD、`iss = prandom`、`rcv_nxt = seq+1`、WS の有無を記録。作成失敗は `table_full++` | SYN-ACK (MSS、WS) |
   | SYN (ACK なし) | あり、SYN_RCVD、`rcv_nxt == seq+1` | 同じ SYN の再送 (SYN-ACK ロス) | 同じ SYN-ACK を再送 |
   | SYN (ACK なし) | あり、ESTABLISHED | RFC 5961 4.2。遅れて届いた重複 SYN で生きた転送を壊さない。再起動した相手は challenge ACK に `rcv_nxt` の RST を返し、SYN を再送してくる | challenge ACK |
   | SYN (ACK なし) | あり、それ以外 (別 ISN の SYN_RCVD、LAST_ACK) | dperf の fast recycle。作り直して `recycled++` (LAST_ACK だったら `recycled_est++` も) | SYN-ACK |
   | ACK, `ack == snd_nxt` | SYN_RCVD | ESTABLISHED、`accepted++`。同乗データがあれば続けて処理 (seq が先に進んでいても確立扱いにし、下の「穴」の行で重複 ACK を返す) | (データ次第) |
   | データ, `seq == rcv_nxt` | ESTABLISHED | `rcv_nxt += len`、`bytes_rcvd += len`、`unacked_segs++` | `unacked_segs >= ack_every` か PSH か FIN なら ACK |
   | データ, `seq < rcv_nxt < seq+len` (一部重複) | ESTABLISHED | 再送で区切りが変わった。`rcv_nxt` より先の部分だけを受理 (RFC 9293 3.10.7.4) | ACK |
   | データ, `seq+len <= rcv_nxt` (重複) | ESTABLISHED / LAST_ACK | 捨てる。末尾が `rcv_nxt` ちょうどなら同乗の FIN は順序どおり | ACK (現在の `rcv_nxt`) |
   | データ, `seq > rcv_nxt` (穴) | ESTABLISHED | 捨てる、`out_of_order++` | 重複 ACK (クライアントの高速再送を促す) |
   | FIN, 順序どおり | ESTABLISHED | `rcv_nxt += 1`、LAST_ACK、`fin_rcvd++` | FIN+ACK (`seq = snd_nxt`、`snd_nxt += 1`) |
   | FIN | LAST_ACK | 自分の FIN+ACK がロスした (相手の FIN 再送) | FIN+ACK を再送 (`seq = snd_nxt-1`) |
   | ACK, `ack == snd_nxt` | LAST_ACK | 削除、`closed++` | なし |
   | SYN 以外 | なし | `stray++` | RST (ACK 付きなら `seq = SEG.ACK`、無ければ `RST|ACK`) |
   | ACK, `ack != snd_nxt` | SYN_RCVD | `unexpected++` | RST (`seq = SEG.ACK`) |

4. 応答は受信フレームをその場で書き換えて XDP_TX する。MAC / IP / ポートの入れ替え、長さ、IPv4 ヘッダチェックサム、
   TCP チェックサム (擬似ヘッダはパケットの IP ヘッダから計算) は、クライアント RX の ACK 生成と同じ
   ヘルパ `tcp_reply_inplace` を共有する。SYN-ACK だけ 8 バイトのオプション (MSS、NOP、WS。WS 不要なら NOP×4) を付ける。
   VLAN 設定時にタグ無しで届いたフレームには `bpf_xdp_adjust_head` でタグを押し戻す。

クライアント側との組み合わせで 1 点変更した: `xdp_tx_tcp` はこれまで全データセグメントに PSH を付けていたが、
フローの最後のセグメントにだけ付けるようにした。`--tcp-ack-every N` のとき、末尾の端数セグメントが PSH で即 ACK され、
RTO を待たずに FIN に進めるため。

### 12.5 Go 側 (pkg/xdperf/tcp_server.go)

| フラグ | 既定 | 意味 |
|---|---|---|
| `--tcp-server` | off | XDP レスポンダ。`--recv` を含意し `--send` を無効にする。`--tcp`、`--swap-resp`、`--rx-device` とは併用不可 |
| `--tcp-listen [ip]:port` | `:5201` | 待ち受け。IP 無しは IPv4 any、`[::]:port` は IPv6 any |
| `--tcp-max-conns` | 262144 | フローテーブルの大きさ (LRU) |
| `--tcp-ack-every` | 1 | N セグメントごとに ACK |
| `--tcp-mss` | 1448 / 1428 (VLAN 時 -4)、MTU 上限 | SYN-ACK で広告する MSS |
| `--tcp-sweep-after` | `max(65 * --tcp-rto, 2s)` | この時間より古い LAST_ACK / SYN_RCVD エントリを回収する |
| `--tcp-vlan-id` / `--tcp-vlan-pcp` | 0 | クライアントと同じ |
| `--duration` | | 指定時間で終了。無指定なら SIGINT / SIGTERM まで |

処理: 待ち受けアドレスの解釈 → `tcp_srv_cfg` 書込 → `xdp_rx_tcp_server` を `--device` に attach → 1 秒ごとに統計表示と
スイーパ (`BatchLookup` で表を舐め、古い LAST_ACK を `closed_implicit`、古い SYN_RCVD を `syn_timeouts` として削除) →
終了時に `tcp server final statistics` (accepted / closed / bytes など。`xdperf-sink` の JSON と同じ意味のフィールド名。
`closed` はデータプレーンの closed とスイーパの closed_implicit の和) を出す。

表示例:

```
tcp-server: active 64 accepted 64 closed 0 | 9.401 Gbps rcvd, 811,922 segs/s, 811,922 acks/s, ooo 0/s, rst 0/s
```

### 12.6 検証 (examples/tcpstream に追加)

- `v4srv` / `v6srv` / `v4vlansrv` / `v6vlansrv`: 受信 ns で `xdperf run --tcp-server` を動かし、`--tcp` クライアントから流す。
  合格条件は送信側 `done == F`、`bytes_acked == F*B`、サーバ側 `accepted == closed == F`、`bytes_rcvd == F*B`。
- `v4ack2`: `--tcp-ack-every 2` で同じことをする (末尾 PSH の確認)。
- `v4linux` / `v6linux`: 送信 ns で Linux の TCP クライアント (`socat`) から `/dev/zero` を B バイト流し、サーバ側の
  `accepted == closed == 1`、`bytes_rcvd == B` を確認する。実スタックとの相互運用性の確認。veth では送信側 veth にも
  XDP プログラムが必要 (10 節の NAPI の件) なので、`xdperf-sink -xdp-pass-dev` を pass 専用に動かす。

### 12.7 実装で分かったこと (veth、1000 フロー同時)

| 事象 | 原因 | 対処 |
|---|---|---|
| フローごとに 1 回ずつ `unexpected` が出て、RTO 待ちで遅くなる | SYN バーストで veth の ring が溢れ、ハンドシェイク ACK と先頭データが落ちた後に 2 番目以降のデータが SYN_RCVD で届く。seq が合わないので捨てていた | Linux と同じく「ack 番号が合えば確立」にし、seq のずれは通常の穴扱い (重複 ACK → 高速再送) にした |
| 1000 フローのうち数個が LAST_ACK に残り `closed` が足りない | クライアントの最終 ACK が ring で落ちる。クライアントは DONE なので何も再送せず、レスポンダにはタイマーが無い | Go 側のスイーパが閾値 (当初 `4 * rto`、13 節で変更) 後に `closed_implicit` として回収。`xdperf-sink` (カーネル TCP) なら FIN を再送してクライアントが再 ACK するので起きない |
| socat が Connection refused になる (テストのみ) | BPF ロードに約 2 秒かかり、attach 前にクライアントが SYN を送ってカーネルが RST した | テストはログの `TCP responder started` を待ってからクライアントを起動する。実運用でも attach 前は RST が返る点に注意 |

### 12.8 制約

- 自前の再送タイマーが無いので、相手が再送してこない限り SYN-ACK / FIN+ACK は再送されない。Linux クライアントは
  SYN / FIN を再送するので実用上は問題ない。
- `--tcp-server` 1 プロセスで 1 待ち受けポート。複数ポートはプロセスを分ける (別デバイスでないと attach が競合する)。
- 固定レスポンス (HTTP 風) の送信、SACK、QinQ、IPv6 拡張ヘッダは未対応。
- 受信した TCP / IPv4 ヘッダのチェックサムは検証しない (クライアント RX も同じ)。ペイロード全体の和を XDP で取ると
  100G でのレスポンダのコストが数倍になるため。壊れたセグメントを ACK すると相手は再送しないので、バイト数は
  「届いたと主張された量」になる。NIC の RX チェックサムオフロード結果を XDP から読めるようになれば
  (`bpf_xdp_metadata_rx_*` に checksum が入れば) そこで落とす。
- 同じフローのパケットが複数の CPU で同時に処理されると、lock が無いので `rcv_nxt` の更新が競合し、受信バイト数を
  二重に数え得る。実 NIC では RSS が 4-tuple で同じキューに振るので起きない。veth では送信 CPU ごとに受信キューが
  決まるので、送信側 (`--tcp` の worker) が複数 CPU から同じフローを送ると崩れ得る。veth で厳密に測るときは
  送信側を 1 worker にする。
- LRU による追い出し (テーブル満杯) は検出できないので、表示上の active には残る。`table_full` が 0 でなければ
  `--tcp-max-conns` を増やす。

## 13. コードレビュー (OCR round 1) への対応

ブロッカー 2 件と要修正 10 件を直した。修正計画は別モデル (Fable) のレビューを受け、その指摘 (下表の「計画レビュー」) も取り込んだ。

| 指摘 | 対応 |
|---|---|
| `--tcp-bytes` >= 4GiB で FIN に到達しない (32bit の seq 差で送信済みバイトを計算) | 64bit の `bytes_acked` から残りを計算する |
| 前回中断したコネクションが相手に残ると再接続できない | SYN_SENT で自分の SYN を確認しない ACK (challenge ACK) を受けたら `<SEQ=SEG.ACK><CTL=RST>` を返し、SYN を 1 回だけ即再送 (`syn_rst`)。2 回目以降は通常のバックオフで再送回数を消費する (計画レビュー: 無限ループ防止)。SYN_SENT の RST は自分の SYN を ACK するものだけ受理する (RFC 9293 3.10.7.3)。FAILED/CLOSED/SKIPPED のフロー宛ての ACK にも RST を返す。中断 (`cfg.abort`) 時は開いているフローに `RST|ACK seq=snd_max` を送る (計画レビュー: snd_nxt は巻き戻し後に相手の RCV.NXT より小さいことがある) |
| レスポンダの状態無しセグメントを黙って捨てる | RFC 9293 3.10.7.1 どおり RST を返す。SYN_RCVD で ack が合わない場合も RST |
| スイーパの snapshot → delete 競合、二重計上 | 削除直前に再 lookup し state/iss/last_ns が同じときだけ削除、削除成功時だけ数える。周期スイーパの終了を待ってから最終スイープ。再送 SYN で `last_ns` を更新 |
| スイーパ閾値 `4 * rto` が相手の FIN 再送間隔より短い (計画レビュー) | `--tcp-sweep-after` を新設、既定 `max(65 * rto, 2s)`。終了時は経過時間に関係なく回収 |
| RTO の巻き戻し後、`snd_nxt` を超える ACK を捨てる | `snd_max` を追加。ACK は `(snd_una, snd_max]` で受理し、`snd_nxt` を追い越したら追従。巻き戻し区間の送信は `rtx_segs` に数える。drain 中も巻き戻し区間は送る (計画レビュー: そうしないと FIN に到達しない)。FIN 送出時も `snd_max` を更新 |
| drain タイムアウトが FIN バックオフより短い、再送に上限が無い | drain タイムアウトを `127 * rto + 1s` に。データの RTO 再送に指数バックオフと上限 (連続 8 回で RST)。FIN_WAIT_2 では `rto << n` ごとに純 ACK で相手の FIN+ACK 再送を促し (レスポンダは LAST_ACK で自分の FIN を含まない ACK を受けたら FIN+ACK を再送)、6 回で RST。drain/abort 開始時に未接続のフローは SKIPPED として閉じた扱い。2 回目の SIGINT と drain タイムアウトで abort し、最大 500ms で終了 |
| `stray` が合算されない | 統計の合算を reflect で全 uint64 フィールドに対して行う (`sumPerCPU`)。全フィールドを検査する単体テスト付き |
| 毎秒表示の `est` が uint64 でアンダーフロー | BPF に `failed_est` (確立後の失敗) を追加し `established - done - failed_est` |
| 相手の MSS を無視 | SYN-ACK の MSS オプションを読み、フローごとに `min(自分の MSS, 相手の MSS)` を使う。オプションが無ければ自分の MSS |
| `--tcp-ack-every N` とクライアントウィンドウ < N で停滞 | クライアントはフロー最後に加えて「次のセグメントがウィンドウに入らない」ときも PSH を付ける (計画レビュー: `==` 判定は MSS が変わると成立しない) |
| ドキュメントが iperf3 / curl と相互運用できると書いている | 一方向に送って閉じるクライアント (socat, nc) に限ると修正 |
| 既定の送信元ポート 40000 がエフェメラル範囲と重なる | 既定を 10000 に変更し、`ip_local_port_range` と重なれば警告 |
| データプレーンの単体テストが無い | `pkg/coreelf/xdp_tcp_test.go` (非 live BPF_PROG_RUN、20 テスト) と `pkg/xdperf/tcp_server_test.go` を追加。example にロスありケース (`v4loss`, `linux4loss`) とレスポンダ相手の再送率上限を追加 |

実装後に Fable が再レビューし「必ず直すべきもの無し」。改善点のうち次を反映: SYN-ACK の窓をスケールしない (RFC 7323)、ESTABLISHED で再送 SYN-ACK に ACK を返す、abort の猶予を `--pps` に合わせて延ばす、レスポンダの active を確立済みフローへの RST (`reset_est`) だけで減らす。ゼロウィンドウプローブ、レスポンダの RST/SYN の seq 検査 (RFC 5961)、シグナル以外の ctx キャンセル時の drain は見送り。

その他: 重複 ACK の判定からウィンドウ更新を除外 (RFC 5681)、相手の FIN は seq の位置が合うときだけ受理、ACK が進んだら高速再送フラグも消す、VLAN 押し戻しの自己代入を削除、`--tcp-window` の上限を 65535 に。

ロス注入の注意: XDP_TX と live frames は qdisc を通らないので、XDP 側の veth に netem を付けても落ちない。カーネルが送る側 (egress netem) と受ける側 (XDP_PASS 後の tc ingress の gact random drop) に入れる。

見送り: 実行ごとに送信元ポートをずらす方式 (RST を落とす中間装置向け)、Suggestions 区分の指摘 (パース処理の共通化、TCP マップの常時ロード、OTLP 対応など)。

## 14. Copilot レビュー (PR #114) への対応

| 指摘 | 対応 |
|---|---|
| xdperf-sink の `-read-buf` が 0 だと空読みで CPU を回し、負数だと panic | 起動時に `> 0` を検査してエラー終了 |
| xdperf-sink に `-v` が無く、`make test-runnable` (CI) が失敗する | `-v` でバージョンを表示して終了 |
| 単体テストが `LastSendNs = 0` と RTO 1e15ns (約 11.6 日) を前提にしており、稼働時間が長いホストで RTO が発火する | 既定の RTO を `1 << 56` ns (約 2.3 年、`<< 6` しても 64bit に収まる) に |
| レスポンダの active が、新しい SYN による確立済みフローの置き換えを反映しない | `recycled_est` を追加して active から引く。LRU の追い出しは検出できないので制約に明記 |
| レスポンダのキーに宛先 IP が無く、ワイルドカード待ち受けで同じ送信元 (IP, ポート) から別の宛先 IP への接続が衝突する | キーに自分の IP (`local`) を追加 |
| IP / TCP の申告長をフレーム長と照合していない | レスポンダとクライアント RX の両方で、状態更新前に検査して DROP |
| 受信チェックサムを検証していない | 見送り。コストの理由を 12.8 に記載 |
| 一部が重複するセグメント (再送で区切りが変わったもの) の新しい部分を捨てる | `rcv_nxt` より先の部分だけ受理する。クライアント RX も同様 |

長さ検査を入れたことで、クライアント送信側の不具合が見つかった。veth でレスポンダ相手に送ると、フルサイズのデータセグメントの一部が
「IP ヘッダは 1488 バイトを名乗るが、フレームは 54 バイト」で出ていた。それまでのレスポンダはこれを 1448 バイトの受信として数えていた。
そのため example のバイト数一致は見かけ上のもので、実際にはヘッダしか運んでいないセグメントがあった。

原因は live frames のフレーム長の扱い。カーネル (`xdp_test_run_batch`) は、プログラムが `data_end` を変えたときしか
`xdp_frame` の長さを更新しない。リサイクルされるページの再初期化 (`reset_ctx`) も、`data` と `flags` が変わったときしか行わない。
テンプレートが最大セグメント長ちょうどだと、フルサイズのセグメントはサイズ調整をしないので `data_end` が変わらない。
その結果、前回そのページを使った側の長さが残る。veth では、対向の XDP プログラムが同じページをその場で 54 バイトの ACK に縮めて返している。
対策として、live frames に渡すフレームを最大セグメント長 + 1 バイトにし、毎回 `bpf_xdp_adjust_tail` が走るようにした。
example のレスポンダケースでは `bad_length == 0` も検査する。

2 回目のレビュー:

| 指摘 | 対応 |
|---|---|
| example の停止処理が、再利用された PID の無関係なプロセスに root で signal を送り得る | signal を送る前に毎回 `/proc/<pid>/comm` を照合する (`pid_is`) |
| xdperf-sink の active 計算で、Accepted → Closed の順に読むとアンダーフローし得る | Closed を先に読む |
| MSS 7 では最大セグメント長 + 1 が SYN の長さと一致し、SYN でフレーム長が更新されない | live frame の長さを max(データ, SYN) + 1 にする |
| `--pps` が小さいと abort の猶予が worker の実行間隔より短く、RST を送れない | 1 worker が全フローを持つ最悪ケースで、必要な実行回数 + 1 回分の間隔の 2 倍を猶予にする |
| スイーパのテストが、起動直後 (1 分未満) のホストで unsigned 減算のアンダーフローを起こす | 起動後 2 分未満ならスキップ |
| 先頭の IPv4 断片 (MF=1, offset 0) を完全なセグメントとして扱う | 断片はすべて XDP_PASS (レスポンダとクライアント RX) |
| 順序外のペイロード無しセグメント (Linux の keepalive、データを追い越した FIN) に ACK を返さず、keepalive で切断される | 現在の `rcv_nxt` で ACK を返す。順序どおりの純 ACK には引き続き返さない |

3 回目のレビュー:

| 指摘 | 対応 |
|---|---|
| MSS 1〜5 では gopacket が 60 バイトまでパディングし、テンプレートの長さ検査で失敗する | `--tcp-mss` の下限を 64 にする (0 は既定値)。データフレームが常に 60 バイト以上かつ SYN オプションより長くなる |
| `--pps` が worker 数より小さいと各 worker に 1 pps が割り当てられ、合計が上限を超える | worker 当たりのレートを小数で持ち、1 pps 未満なら実行間隔を 1 秒より延ばす |
| レスポンダが最終スイープと統計取得の時点でまだ attach されたまま | 先に detach してから最終スイープと集計を行う (defer は早期 return 用に残す) |

4 回目のレビュー:

| 指摘 | 対応 |
|---|---|
| `--duration` と `--pps` から計算するリプレイ用の Count が TCP モードにも適用され、`--pps` < `--parallelism` で起動を拒否される | TCP モード (`--tcp` / `--tcp-server`) では Count の計算と検査をしない |
| example でログの切り詰めが子プロセス側で行われ、準備完了チェックが前のケースのログを読み得る | 起動前に親シェルでレスポンダとシンクのログを空にする |

## 15. codex レビューへの対応、CI での verifier 拒否

PR の CI (`test` と `examples`) は最初のコミットから落ちていた。GitHub の ubuntu-24.04 ランナーのカーネルが、
`xdp_tx_tcp` を「invalid read from stack R1 var_off (0x0; 0x1f)+16 size 1」で拒否していた。
`hdr + l3_off` (可変オフセットのスタックポインタ) 経由で IP ヘッダを編集していたのが原因。
同じオブジェクトに入っている UDP 側のプログラムも巻き添えで読み込めず、全シナリオが失敗していた。
手元のカーネル 7.0 と、vimto の 6.1〜7.2 では受理されていた。

IP ヘッダを専用のバッファに定数オフセット (l3_off は 14 か 18) でコピーして編集するようにした。
`bpftool -d prog loadall` の verifier ログで可変オフセットのフレームポインタ (`fp(off=...,var_off...)`) を数えると、
修正前 282 命令、修正後 0。CI の examples に socat を入れ、カーネル TCP クライアントのケース (linux4, linux6, linux4loss) も
SKIP せずに走らせる。BPF load test の vimto 実行に TCP データプレーンのテスト (`-run TestTcp`) を加えた。

codex (差分を標準入力で渡す形。この環境ではサンドボックスが起動しないため) のレビュー:

| 指摘 | 対応 |
|---|---|
| 相手のウィンドウが MSS 未満だと最初のセグメントを送れず、何も飛んでいないので RTO も働かず停止する。ゼロウィンドウでウィンドウ更新を落とすと永久に停止する | 何も飛んでいないときはウィンドウに収まる長さに縮めて送る。ウィンドウが閉じて何も飛んでいなければ、RTO ごとに古い seq (`snd_una - 1`) の純 ACK を送って相手に現在のウィンドウを返させる (persist。諦めない)。`window_probes` で数える |
| レスポンダで、確立済みフローに遅れて届いた重複 SYN がフローを作り直し、転送を壊す | ESTABLISHED への SYN には challenge ACK (RFC 5961 4.2)。LAST_ACK と別 ISN の SYN_RCVD は従来どおり作り直す |
| 確立後の RST を seq に関係なく受理する (クライアント、レスポンダとも) | `seq == rcv_nxt` だけ受理し、それ以外は challenge ACK (RFC 5961 3.2)。SYN_RCVD のレスポンダは捨てる。`challenge_acks` で数える |
| 古い ACK や `snd_max` を超える ACK が送信ウィンドウを上書きする | `snd_una <= ack <= snd_max` の ACK でだけウィンドウを更新する |
| 同じフローを複数 CPU が同時に処理するとレスポンダの状態更新が競合する | 対応せず制約として明記 (12.8)。実 NIC は RSS で同じフローを同じキューに振る。veth で送信側の worker が複数だと、送信 CPU ごとに受信キューが分かれて崩れ得る |
| 全フローが失敗しても終了コードが 0 | `failed > 0` ならエラーを返す (中断・再送断念・FIN_WAIT_2 タイムアウトの内訳つき) |
| 統計表示の goroutine の終了を待っていない | 終了を待ってから最終統計を出す (クライアント、レスポンダとも) |
| 最低対応カーネルで TCP データプレーンのテストを回していない | vimto の全カーネルで `-run TestTcp` を実行 |
