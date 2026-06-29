# src/ eBPF/XDP コードアーキテクチャ解説

XDPerfのカーネル側パケット処理を担うeBPF/XDPプログラム群の設計と実装を解説する。

## ファイル構成

```
src/
├── xdp_prog.h      共通定義（統計構造体、RXマップ、デバッグマクロ）
├── xdp_utils.h     ユーティリティ（MAC/IPスワップ、swap_resp制御）
├── xdp_packet.h    データ構造とBPFマップ定義（システムの心臓部）
├── xdp_checksum.h  チェックサム計算エンジン（フル再計算用）
└── xdp_prog.c      XDPプログラム本体（TX/RX/チェックサム）
```

## 設計思想: Diffベースパケット生成

全パケットをコピーする代わりに「**ベースパケット + 差分（Diff）**」だけを持つ。メモリ効率が高く、CPUキャッシュにも優しい。

```
base_packet_map[0] = [Ethernet + IP + UDP + payload ...]  （1回だけコピー）
diff_map[0] = { base_idx=0, diffs=[{offset=36, new=port8080}] }
diff_map[1] = { base_idx=0, diffs=[{offset=36, new=port8081}] }
→ ベースに差分を適用するだけで異なるパケットを生成
```

## ヘッダファイル詳細

### xdp_prog.h — 共通基盤

統計用構造体とRX統計マップを定義。

```c
struct datarec {
    __u64 packets;          // パケット数
    __u64 bytes;            // バイト数
    __u64 diff_errors;      // diff適用失敗数
    __u64 checksum_errors;  // チェックサム計算失敗数
};
```

`DEBUG_PRINT`マクロでコンパイル時に`bpf_printk`を有効/無効化。

### xdp_utils.h — スワップユーティリティ

サーバーモード（`xdp_rx`）で受信パケットを返送する際のMAC/IPアドレススワップ関数群。`volatile __u32 swap_resp`でGo側から有効/無効を制御する。

> パケットキャプチャは外部ツール [xdp-ninja](https://github.com/takehaya/xdp-ninja) を使う。fentry/fexit で稼働中のXDPプログラムに非侵襲アタッチするため、XDPプログラム側にフック（旧 `xdpcap.h` の `RETURN_ACTION` / `xdpcap_hook`）を埋め込まない。GTP-U等のカプセル化内側ヘッダもDSLでフィルタできる。

### xdp_packet.h — データ構造とBPFマップ（最重要）

#### 定数

| 定数 | 値 | 用途 |
|------|-----|------|
| `MAX_PACKET_SIZE` | 2048 | パケットの最大バイト数 |
| `MAX_DIFFS_PER_PACKET` | 8 | 1エントリあたりの最大diff数 |
| `MAX_DIFF_ENTRIES` | 131072 | CPU毎の最大diffエントリ数 |
| `MAX_CHECKSUM_ENTRIES` | 4 | ベースパケット毎の最大チェックサム数 |
| `MAX_BASE_PACKETS` | 16 | ベースパケットの最大バリアント数 |

これらは`volatile`変数としてGoからも参照可能。

#### 構造体

**`base_packet`** — ベースパケット本体
```c
struct base_packet {
    __u16 len;                  // パケット長
    __u8 checksum_count;        // チェックサム数
    __u8 data[MAX_PACKET_SIZE]; // パケットデータ
};
```

**`diff_value`** — 単一の差分値
```c
struct diff_value {
    __u8 old_value[8];   // 変更前の値（チェックサム差分計算用）
    __u8 new_value[8];   // 変更後の値（パケットに書き込む値）
    __u16 offset;        // パケット内のバイトオフセット
    __u8 size;           // サイズ: 1, 2, 4, 6, 8
    __u8 affects_csum;   // ビットマスク: bit i = checksum[i]に影響（Goホストが事前計算）
};
```

`affects_csum`はGoホスト側でdiffのオフセット範囲と各チェックサムのカバー範囲を比較して計算。BPF側ではビットテスト1回で判定できる。

**`diff_entry`** — 1パケット分の差分セット
```c
struct diff_entry {
    struct diff_value diffs[8];  // 最大8つの差分スロット
    __u16 pkt_len;               // パケット長
    __u8 base_idx;               // ベースパケットのインデックス
    __u8 diff_count;             // 有効なdiff数（キャッシュ後に増加）
    __u8 len_changed;            // ベースと長さが異なるか
    __u8 csum_cached;            // チェックサムがdiffとしてキャッシュ済みか
};
```

`csum_cached=1`のとき、チェックサム値がdiffsスロットに格納されており、チェックサム計算を完全にスキップできる。

**`checksum_meta`** — チェックサム再計算のメタデータ
```c
struct checksum_meta {
    __u16 csum_offset;      // チェックサムフィールドのオフセット
    __u16 header_start;     // チェックサム対象ヘッダの先頭
    __u16 header_len;       // ヘッダ長（0=IP/トランスポート長から自動計算）
    __u16 ip_header_offset; // IPヘッダのオフセット
    __u8 ip_version;        // IPバージョン（4 or 6、Goホストがキャッシュ）
    __u8 ip_protocol;       // IPv4 protocolフィールド or IPv6 next headerフィールドの値（Goホストがキャッシュ）
                            // ※ IPv6拡張ヘッダがある場合、最終トランスポートプロトコルとは限らない
};
```

`ip_version`はGoホストがベースパケットのIPヘッダ先頭バイトから読み取ってセット。`ip_protocol`はIPv4のprotocolフィールド（offset 9）またはIPv6固定ヘッダのnext headerフィールド（offset 6）の値。IPv6拡張ヘッダ（SRH等）がある場合は中間ヘッダの値であり、最終トランスポートプロトコルとは一致しない場合がある。BPF側でパケットから毎回ロードする必要をなくし、`bpf_xdp_load_bytes`呼出を削減する。

**`pkt_state`** — CPU毎のパケット送信状態
```c
struct pkt_state {
    __u32 count;         // 有効なdiffエントリ数
    __u32 idx;           // 現在のインデックス（ラウンドロビン）
    __u32 last_base_idx; // 前回のbase_idx（0xFFFFFFFF=初回強制コピー）
};
```

`last_base_idx`によりベースパケットが変わっていなければコピーを省略できる。

#### BPFマップ一覧

データマップは全て`BPF_MAP_TYPE_PERCPU_ARRAY`であり、CPU間のロック競合がない。これが高PPSの基盤。`xdp_progs`のみ`BPF_MAP_TYPE_PROG_ARRAY`（tail call用）。

| マップ | エントリ数 | 用途 |
|--------|-----------|------|
| `base_packet_map` | 16 | ベースパケット本体 |
| `diff_map` | 131072（動的変更可） | 差分エントリ |
| `checksum_meta_map` | 64 (16×4) | チェックサムメタデータ |
| `pkt_state_map` | 1 | CPU毎のラウンドロビン状態 |
| `tx_stats_map` | 1 | 送信統計 |
| `tail_call_ctx_map` | 1 | tail call間のコンテキスト受け渡し |
| `xdp_progs` | 2 (PROG_ARRAY) | tail call先プログラム |

### xdp_checksum.h — チェックサム計算エンジン

フル再計算（O(パケット長)）のための関数群。`bpf_loop`とコールバックでverifier命令数制限を回避する。

| 関数 | 用途 |
|------|------|
| `calc_ipv4_header_csum` | IPv4ヘッダチェックサム（RFC 1071） |
| `calc_transport_csum_ipv4` | IPv4上のTCP/UDPチェックサム（疑似ヘッダ付き） |
| `calc_transport_csum_ipv6` | IPv6上のTCP/UDP/ICMPv6チェックサム（SRv6対応） |

IPv6版は`final_dst`パラメータでSRHの最終宛先アドレスを疑似ヘッダに使用する（RFC 8200/8754準拠）。

## xdp_prog.c — XDPプログラム本体

### プログラム全体フロー

```
                    ┌──────────────┐
  受信パケット ───→ │   xdp_rx     │ ───→ XDP_TX (スワップ応答) / XDP_DROP
                    └──────────────┘

                    ┌──────────────────┐
  BPF_PROG_RUN ──→ │     xdp_tx       │
                    │                  │
                    │ 1. 状態取得      │
                    │ 2. diff取得      │
                    │ 3. base取得      │
                    │ 4. サイズ調整    │
                    │ 5. コピー判定    │
                    │ 6. diff適用      │
                    │ 7. csum_cached?  │
                    │    YES → XDP_TX  │─── ホットパス（2回目以降、固定長・IMIX両対応）
                    │    NO  → tail call│
                    └──────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
  ┌───────────────────┐    ┌─────────────────────┐
  │ xdp_tx_checksum   │    │ xdp_tx_csum_diff    │
  │ (len_changed=1)   │    │ (len_changed=0)     │
  │                   │    │                     │
  │ update_lengths    │    │ インクリメンタル    │
  │ recalc_checksum   │    │ bpf_csum_diff       │
  │ cache_csum_to_diffs│   │ cache_csum_to_diffs │
  │ (長さ+csum格納)   │    │ (csumのみ格納)      │
  │ → XDP_TX          │    │ → XDP_TX            │
  └───────────────────┘    └─────────────────────┘

  ※ 初回のみ tail call。計算結果（+ len_changed時は長さフィールド値も）を
    diff_entryにキャッシュし、2回目以降はxdp_tx内で完結（tail callなし）。
    SRv6/MPLSネストパケットはキャッシュを安全にスキップし毎回フル計算。
```

### 各関数の詳細

#### `xdp_pass_dummy` — ダミープログラム

XDP_PASSを返すだけ。NICドライバがXDP用TX Queueを確保するために、実パケット送信前にアタッチする必要がある。

#### `xdp_rx` — 受信プログラム

VLAN/QinQをパースしてIPv4/IPv6を検出。`swap_resp=1`ならMAC/IPをスワップしてXDP_TXで返送する（サーバーモード）。統計をカウントしてRXマップに記録。

#### `copy_base_packet` — ベースパケットコピー

`__noinline`でverifier状態を隔離。64バイトチャンクで最大32回ループしてパケットバッファにコピー。呼び出し元でテールコピー（最後の64バイトを再コピー）して端数をカバーする。

```c
// 64Bチャンク × 最大32回 = 2048Bまで対応
for (int chunk = 1; chunk <= MAX_COPY_CHUNKS; chunk++) {
    bpf_xdp_store_bytes(ctx, offset, base->data + offset, COPY_CHUNK_SIZE);
}
```

kernel 6.1のverifierは変数オフセットを追跡できないため、`offset >= MAX_PACKET_SIZE`と`target_len <= offset`の二重チェックで境界を証明する。

#### `apply_diff` — 差分適用

`bpf_xdp_store_bytes`でパケットバッファの指定オフセットに`new_value`を書き込む。switch文でサイズ毎に定数リテラルを使用（verifierが変数サイズを受理しないため）。

#### `capture_old_values` — バッファ実値の取り込み

ベースパケットコピーが省略され、かつ`csum_cached=0`（初回）の場合のみ呼ばれる。各diffオフセットのバッファ実値を`bpf_xdp_load_bytes`で読み取り、`old_value`フィールドに格納する。これによりインクリメンタルチェックサムが正しいシード値を使える。`csum_cached=1`のときはチェックサム計算自体をスキップするため不要。

#### `ipv6_find_transport` — IPv6拡張ヘッダ走査

Hop-by-Hop Options、Routing Header（SRH含む）、Fragment Header、Destination Optionsを最大4段辿り、トランスポート層（UDP/TCP/ICMPv6）を発見する。

SRHを検出した場合、Segments Left > 0ならsegment[0]（最終宛先）を取得。RFC 8754に従い、チェックサム疑似ヘッダにこのアドレスを使用する。

IPPROTO_ETHERNET (143)、IPPROTO_IPIP (4)、IPPROTO_IPV6 (41)もターミナルプロトコルとして認識し、SRv6 L2VPN/L3VPNをサポートする。

#### `xdp_tx` — メイン送信プログラム

パケット生成の全体を制御する中心関数。処理ステップ:

**1-3. マップ参照**
```
pkt_state_map → idx取得 → diff_map[idx] → base_idx取得 → base_packet_map[base_idx]
```

**4-5. サイズ調整とコピー判定**

`bpf_xdp_adjust_tail`でパケットサイズを調整後、コピーが必要か判定:

```c
if (target_len <= COPY_CHUNK_SIZE) {
    need_copy = true;   // 64B以下: コピーが1回のhelper呼出で済むので常にコピー
} else {
    need_copy = (base_idx != state->last_base_idx) || (cur_len != target_len);
    state->last_base_idx = base_idx;
}
```

- ベースが変わった or パケット長が変わった → コピー実行
- 同じベース・同じ長さ → コピー省略（XDP TXはパケットをリサイクルするのでバッファが残る）
- 64B以下 → 常にコピー（省略のオーバーヘッドが savings を超えるため）

**6. diff適用とコピー省略時の old_value 取り込み**

コピーを省略した場合かつ`csum_cached=0`（初回）のときのみ、`capture_old_values`でバッファの実値をold_valueに取り込む。これはインクリメンタルチェックサムの正確性に必須（バッファには前回のnew_valueが残っているため）。`csum_cached=1`のときはチェックサム計算自体をスキップするので取り込み不要。

**7. チェックサムキャッシュ判定**

```c
if (diff->csum_cached) {
    // チェックサム値はdiffsに含まれており、apply_diffで既に書き込み済み
    update_stats_and_index(...);
    return XDP_TX;  // tail callなしで直接返す
}
```

**`csum_cached=1`のとき、tail callチェーン全体をスキップ。** diff適用（ステップ6）でチェックサム値も書き込み済みなので、追加計算は不要。これにより2回目以降のパケットは`xdp_tx`だけで完結する。

**8. 初回のみ: tail call**

`csum_cached=0`（初回）のときのみ`tail_call_ctx_map`にコンテキストを格納し、`xdp_tx_checksum`にtail callする。

#### `cache_one_diff` — キャッシュ書き込みヘルパー

diff_entryの指定スロットに値を書き込む。switch文で定数インデックスに展開し、`__noinline`でコンパイラの最適化（switch→変数演算への変換）を防止。kernel 6.1のverifierは変数インデックスでのmap valueアクセスを拒否するため必須。

#### `cache_csum_to_diffs` — チェックサム結果のキャッシュ

チェックサム計算完了後に呼ばれ、計算結果をdiff_entryに追記する。`len_changed`の有無で処理が分岐する。

**`len_changed=0`（固定長パケット）の場合:**

チェックサム値のみをキャッシュする。

```
キャッシュ前:  diffs=[{port変更}],                    diff_count=1, csum_cached=0
キャッシュ後:  diffs=[{port}, {ipv4_csum}, {udp_csum}], diff_count=3, csum_cached=1
```

**`len_changed=1`（IMIX等の可変長パケット）の場合:**

長さフィールド値とチェックサム値の両方をキャッシュする。長さフィールドのオフセットは`checksum_meta`から導出する:
- IPv4: `ip_header_offset + 2`（tot_len）
- IPv6: `ip_header_offset + 4`（payload_len）
- UDP: `header_start + 4`（UDP length）

```
キャッシュ前:  diffs=[{port変更}],        diff_count=1, csum_cached=0
キャッシュ後:  diffs=[{port}, {ip_tot_len}, {udp_len}, {ipv4_csum}, {udp_csum}],
              diff_count=5, csum_cached=1
```

**安全ガード（ネストパケット対応）:**

SRv6/MPLSでカプセル化された内部パケットの長さフィールドは`checksum_meta`だけでは列挙できない。以下の条件でキャッシュを安全にスキップし、毎回フル計算にフォールバック:

1. **MPLSパケット**: EtherTypeがMPLS → 即時return
2. **SRv6等のカプセル化**: `checksum_meta.ip_header_offset`がEthernet/VLANパース結果のL3 offsetと不一致 → return
3. **スロット不足**: `diff_count + 長さdiff数 + checksum数 > 8` → return
4. **途中のエラー**: マップ参照失敗/パケット読み取り失敗 → return（`csum_cached`をセットしない）

**重複排除:**

IPv4ヘッダチェックサムとUDPチェックサムが同じ`ip_header_offset`を持つ場合、IP tot_lenのオフセットが重複する。小さな配列（最大8エントリ）で既出オフセットを追跡し、同じオフセットのキャッシュをスキップする。

**`csum_cached=1`のセット条件:**

全てのチェックサム値が格納成功した場合のみ。部分キャッシュ（一部のチェックサムだけ格納）は不正パケットの原因になるため、ALL or NOTHINGで動作する。

#### `update_stats_and_index` — 統計更新とインデックス進行

ラウンドロビンインデックスを`(idx + 1) % count`で更新し、送信統計（パケット数、バイト数、エラー数）を記録。チェックサムプログラムと`xdp_tx`（キャッシュ済みパス）の両方から呼ばれる。

#### `xdp_tx_checksum` — チェックサム処理（`len_changed`パス）

tail callで`xdp_tx`から呼ばれる（初回のみ。`csum_cached=1`の場合はtail callがスキップされる）。`len_changed=0`なら即座に`xdp_tx_csum_diff`にtail call。

`len_changed=1`の場合:
1. `update_packet_lengths` — VLAN/QinQ/MPLSをパースし、IPv4 total_len、IPv6 payload_len、UDP lengthを更新。SRv6 L2VPN/L3VPNの内部パケット長も更新する。
2. `recalc_checksum` — 各チェックサムをフル再計算。`meta->ip_version`のキャッシュ値を使用。
3. `cache_csum_to_diffs` — 長さフィールド値とチェックサム値をdiff_entryにキャッシュ（条件付き）。キャッシュ成功後は2回目以降のパケットでこの関数自体が呼ばれなくなる。

#### `recalc_checksum` — フルチェックサム再計算

`checksum_meta`のキャッシュ済み`ip_version`で分岐:

- IPv4ヘッダチェックサム: `calc_ipv4_header_csum`（疑似ヘッダなし）
- IPv4トランスポート: `calc_transport_csum_ipv4`（疑似ヘッダ付き）、ICMP時は`calc_ipv4_header_csum`
- IPv6トランスポート: `ipv6_find_transport`で拡張ヘッダを辿った後`calc_transport_csum_ipv6`

#### `xdp_tx_csum_diff` — インクリメンタルチェックサム

`len_changed=0`のときに使用。`bpf_csum_diff`で変更前後の差分だけを計算し、既存チェックサムに加算する。

```c
// bpf_loopで各diffをコールバック処理
bpf_loop(diff_count, csum_diff_loop_callback, &loop_ctx, 0);
```

**`affects_csum`ビットマスクで高速判定:**
```c
if (!(dv->affects_csum & (1 << csum_idx)))
    return csum;  // このdiffはこのチェックサムに影響しない → スキップ
```

Goホストが事前計算したビットマスクにより、パケットからIPバージョンやプロトコルをロードする必要がない。

#### `apply_single_csum_diff` — 単一diff のチェックサム差分計算

奇数/偶数オフセットに応じたパディングを行い、`bpf_csum_diff`を呼ぶ。ネットワークバイトオーダー（ビッグエンディアン）のチェックサムは16ビットワード境界で計算するため、バイト位置に応じた配置が必要。

## Verifier対策パターン

kernel 6.1のBPF verifierの制約に対処するための設計パターンが随所に見られる。

| 手法 | 理由 | 使用箇所 |
|------|------|---------|
| `__noinline` | 関数をverifier状態空間から隔離 | `copy_base_packet`, `apply_diff`, `recalc_checksum`等 |
| switch文での定数インデックス | 変数オフセットのmap valueアクセスを拒否するverifier回避 | `csum_diff_loop_callback`, `cache_one_diff` |
| `bpf_loop` + コールバック | bounded loopの状態爆発回避 | チェックサム計算のdiffイテレーション |
| tail call分割 | 1プログラムあたり1M命令制限の回避 | `xdp_tx` → `xdp_tx_checksum` → `xdp_tx_csum_diff` |
| 二重境界チェック | `umin > umax`状態のプルーニング不備回避 | `copy_base_packet`のoffsetチェック |
| 呼び出し元でのテールコピー | `__noinline`境界でのmap_value型追跡の喪失回避 | `xdp_tx`内のtail_off計算 |

## 性能最適化の層

1. **データマップが全てPERCPU** — CPU間ロックなし
2. **Diffベース** — フルパケットコピー不要、変更箇所のみ書き込み
3. **条件付きコピー省略** — 同一ベース・同一長なら`copy_base_packet`をスキップ
4. **チェックサムキャッシュ** — 初回計算後にdiffとしてキャッシュ、2回目以降はtail callなしで直接XDP_TX。固定長・IMIX（可変長）の両方に対応
5. **長さフィールドキャッシュ** — `len_changed`時、`update_packet_lengths`が書いたIP/UDP長フィールド値もdiffとしてキャッシュ。2回目以降は`update_packet_lengths`自体をスキップ（ネストパケットは安全にフォールバック）
6. **affects_csumビットマスク** — チェックサム影響判定をパケット読み取りからビットテストに置換
7. **checksum_metaキャッシュ** — IPバージョン/プロトコルをGoホスト側で事前格納、パケット読み取りを削減
8. **キャプチャフック非搭載** — XDPプログラムにキャプチャ用の分岐を一切持たない（観測は外部 xdp-ninja が fentry/fexit で行う）

## 性能測定結果（Intel ICE NIC, 50 cores, batch-size=64）

| ワークロード | 最適化前 | 最適化後 | 改善 |
|-------------|---------|---------|------|
| 固定長 64B | 107 Mpps / 87 Gbps | 190 Mpps / 154 Gbps | +78% |
| IMIX (64-1500B混合) | 24 Mpps / 22 Gbps | 147 Mpps / 258 Gbps | +520% |
