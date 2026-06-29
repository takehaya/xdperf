# パフォーマンス最適化計画

## 現状整理

### 計測環境
- virtio-net ドライバ上のVM
- batch-size=64（キャプチャフックは廃止済み。観測は外部 xdp-ninja）

### 現在の性能 (diff方式導入後)

| 条件 | 性能 |
|------|------|
| 1 core, diff方式 | ~3.3 Mpps |
| 15 core, diff方式 (count=10k) | ~50 Mpps |
| 15 core, diff方式 (count=15) | ~59 Mpps |
| 1 core, 書き換えなし (no-op) | ~5 Mpps |
| 15 core, 書き換えなし (no-op) | ~69 Mpps |

### ボトルネック分析

1coreあたり約2Mppsがdiff方式のオーバーヘッド。原因は `xdp_tx` + `xdp_tx_checksum` で発生するBPFヘルパー呼び出し数の多さ:

**xdp_tx (1パケットあたり):**
| 処理 | ヘルパー呼び出し回数 |
|------|---------------------|
| map lookup (pkt_state, diff, base_packet) | 3回 |
| bpf_xdp_adjust_tail | 0~1回 |
| bpf_xdp_store_bytes (ベースパケットコピー, 64Bチャンク) | 1~32回 |
| apply_diff (bpf_xdp_store_bytes) | 0~8回 |
| tail_call_ctx_map lookup + bpf_tail_call | 2回 |

**xdp_tx_checksum (tail call先, 1パケットあたり):**
| 処理 | ヘルパー呼び出し回数 |
|------|---------------------|
| tail_call_ctx_map lookup | 1回 |
| diff_map lookup (2回目) | 1回 |
| checksum_meta_map lookup | チェックサム数分 |
| bpf_csum_diff / bpf_xdp_load_bytes | 複数回 |
| pkt_state_map lookup | 1回 |
| tx_stats_map lookup | 1回 |

最小構成 (64Bパケット, diff 1個, チェックサム 1個) でも **15回以上のヘルパー呼び出し**。
retpoline有効環境ではindirect callに数十ns加算されるため、これだけで500ns以上のオーバーヘッドになる。

---

## 最適化方針

### 方針1: Fast Path — diff/チェックサムなしの場合にtail callをスキップ

**期待効果: 高 (rawモード/単一パケット時)**

現在、全パケットが必ず `bpf_tail_call` → `xdp_tx_checksum` を通る。
diffなし・チェックサムなしの場合は `xdp_tx` 内で直接 stats更新 → XDP_TX を返せる。

tail call + `xdp_tx_checksum` 内の map lookup群 (5回以上) を全スキップ。

```c
// xdp_tx の末尾、tail callの手前に追加:
if (diff_count == 0 && base->checksum_count == 0) {
    // Fast path: skip tail call entirely
    state->idx = (local_idx + 1 >= count) ? 0 : local_idx + 1;
    struct datarec *rec = bpf_map_lookup_elem(&tx_stats_map, &zero);
    if (rec) {
        rec->packets++;
        rec->bytes += target_len;
    }
    return XDP_TX;
}
```

**対象ユースケース:**
- rawモード (プラグインが生パケットを返す場合)
- blast mode (単一パケットの最大pps)
- Variableモードでもdiff数0のエントリ (ベースパケットそのままのラウンド)

### 方針2: ベースパケットコピーをdirect packet accessに変更

**期待効果: 高 (全パケットサイズ)**

現在64Bチャンク × N回の `bpf_xdp_store_bytes` でベースパケットをコピーしている。
1500Bパケットなら約24回のヘルパー呼び出し。

XDPではdirect packet access (`ctx->data` ポインタ経由の `__builtin_memcpy`) が使える。
ヘルパー呼び出しゼロでコピー可能。

**課題:** `__builtin_memcpy` はコンパイル時に長さが定数である必要がある (BPF verifier制約)。

**解決策A: サイズ段階別の分岐**
```c
// よくあるパケットサイズでswitch
if (target_len <= 64) {
    __builtin_memcpy(data, base->data, 64);
} else if (target_len <= 128) {
    __builtin_memcpy(data, base->data, 128);
} else if (target_len <= 256) {
    __builtin_memcpy(data, base->data, 256);
} else if (target_len <= 512) {
    __builtin_memcpy(data, base->data, 512);
} else if (target_len <= 1024) {
    __builtin_memcpy(data, base->data, 1024);
} else if (target_len <= 1536) {
    __builtin_memcpy(data, base->data, 1536);
} else {
    __builtin_memcpy(data, base->data, 2048);
}
```

**解決策B: 常にMAX_PACKET_SIZEバイトコピー**

パケットが常にMAX_PACKET_SIZE (2048B) 以上確保されているなら、
常に固定長でコピーして余分はbpf_xdp_adjust_tailで切る。
分岐なし・ヘルパー呼び出し0回。

```c
if (data + MAX_PACKET_SIZE <= data_end) {
    __builtin_memcpy(data, base->data, MAX_PACKET_SIZE);
}
// adjust_tailで正しい長さに
```

**注意点:**
- `bpf_xdp_store_bytes` 後はポインタ再取得不要だが、direct access後は不要 → verifier対応がシンプルになる可能性
- `base->data` はPERCPU_ARRAYのmap valueポインタなので、直接参照可能
- 大きい定数memcpyはインストラクション数制限に注意 (特にunrollされる場合)

### ~~方針3: Pre-built packet方式~~ (検証済み・不採用)

事前にフルビルドしたパケットをマップに入れてコピーする方式を検証済み。
結果として、**フルパケットのmemcpyの方がdiff適用より遅い**ことが確認された。
diff方式はベースパケットコピー後に数バイトの差分だけ書き換えるため、
メモリ帯域の消費が少なく、特にパケット数が多い場合に有利。

→ **diff方式を前提として、diff処理自体の高速化に注力する。**

### 方針3: diff_mapの2回lookupを排除

**期待効果: 中**

現在 `diff_map` は `xdp_tx` と `xdp_tx_checksum` で2回lookupされている。

**解決策A: tail_call_ctx にdiff情報を埋め込む**

`tail_call_ctx` 構造体にdiffsの配列を含めることで、`xdp_tx_checksum` 側のdiff_map lookupを省略。
```c
struct tail_call_ctx {
    // 既存フィールド...
    struct diff_value diffs[MAX_DIFFS_PER_PACKET]; // 追加
    __u8 diff_count;                                // 追加
};
```

**解決策B: BPF global変数をコンテキスト受け渡しに使う**

PERCPU global変数 (`.bss` セクション) でtail call間のコンテキストを受け渡す。
map lookupのオーバーヘッドを完全に排除。

```c
// global per-CPU context (no map lookup needed)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    // ... 既存と同じだがglobal変数で代替可能か要検証
} tail_call_ctx SEC(".bss");
```

**注意:** BPF global変数はper-CPU自動対応ではないため、PERCPU_ARRAYのままがよい可能性が高い。
代わりに、tail_call_ctxにdiff情報を埋め込む方式A が現実的。

### 方針4: チェックサムのincremental update最適化

**期待効果: 中 (チェックサムありの場合)**

現在の `apply_csum_with_bpf_diff` はdiffごとに `bpf_csum_diff` を呼ぶ。
複数diffを1回の `bpf_csum_diff` にまとめられれば呼び出し回数を削減できる。

また、`diff_affects_checksum` で毎回IPヘッダを読み直している。
base_idxごとにチェックサムタイプ (IPv4 header / IPv4 transport / IPv6 transport) を
`checksum_meta` に事前計算して格納しておけば、ランタイムの判定を省略できる。

### 方針5: カーネル設定の最適化

**期待効果: 高 (特にmlx5/iceドライバ)**

#### 現状 (6.15.0-rc6-btf-fixed+)

カーネル6.x系では`CONFIG_RETPOLINE`が`CONFIG_MITIGATION_RETPOLINE`にリネームされている。
現在の環境では以下が全て有効:

```
CONFIG_CPU_MITIGATIONS=y
CONFIG_MITIGATION_RETPOLINE=y          # indirect call penalization
CONFIG_MITIGATION_RETHUNK=y            # return thunk
CONFIG_MITIGATION_CALL_DEPTH_TRACKING=y
CONFIG_MITIGATION_SPECTRE_V2=y
CONFIG_MITIGATION_SPECTRE_BHI=y        # Branch History Injection
CONFIG_MITIGATION_IBRS_ENTRY=y
```

ランタイムでは `spectre_v2: Enhanced / Automatic IBRS` と表示されており、
CPUがeIBRSをサポートする場合はカーネルがretpolineよりIBRSを優先する。
ただしIBRS自体もindirect branch predictionに介入するため、オーバーヘッドはゼロではない。

#### 対策

```bash
# ブートパラメータで全mitigation無効化
mitigations=off
```

これにより retpoline, IBRS, rethunk, call depth tracking, BHI 等が全て無効になる。
BPFヘルパー呼び出し1回あたり数ns~数十nsの差が出るため、
1パケット15回以上のヘルパー呼び出しがある現状では有意な差になる可能性がある。

**注意:** `mitigations=off`はセキュリティリスクがあるためベンチマーク専用にすること。

cf. https://github.com/xdp-project/xdp-tools/issues/536
cf. https://github.com/xdp-project/xdp-paper/tree/main/benchmarks

方針1~4のヘルパー呼び出し削減と組み合わせると効果が倍増する。

---

## 優先度と実装順序

| 優先度 | 方針 | 難易度 | 期待効果 | 備考 |
|--------|------|--------|----------|------|
| **1** | 方針1: Fast Path (tail callスキップ) | 低 | 高 | rawモード/blast modeで即効果 |
| **2** | 方針2: direct packet access | 中 | 高 | verifier対応が鍵 |
| **3** | 方針3: diff_map 2回lookup排除 | 低 | 中 | tail_call_ctx拡張で対応 |
| **4** | 方針4: チェックサム最適化 | 中 | 中 | checksum_metaの拡張 |
| **5** | 方針5: カーネル設定 | 低 | 高 | ユーザー向けドキュメント |

**注:** Pre-built packet方式は検証済みで不採用。フルパケットのmemcpyはdiff適用より遅い。

### 実装フェーズ案

**Phase 1: 低コストで大きな効果**
- 方針1 (Fast Path) を実装 → rawモード/blast modeの性能を即改善
- 方針3 (diff_map 2回lookup排除) も合わせて実装 (低難度)

**Phase 2: コピー最適化**
- 方針2 (direct packet access) を実装
- verifierテストを十分に行う

**Phase 3: チェックサム最適化**
- 方針4を実装
- Variableモードでの性能改善

---

## 計測方針

各最適化の効果を以下の条件で計測する:

```bash
# 1 core baseline
sudo ./out/bin/xdperf run --device=<dev> --count 1k --parallelism 1 --infinite --batch-size 64 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200}'

# Multi core baseline
sudo ./out/bin/xdperf run --device=<dev> --count 10k --parallelism 15 --infinite --batch-size 64 --cfg '...'

# Small map (最大pps)
sudo ./out/bin/xdperf run --device=<dev> --count 15 --parallelism 15 --infinite --batch-size 64 --cfg '...'
```

### 目標値
- 1 core: 3.3Mpps → **5Mpps** (no-op同等)
- 15 core: 59Mpps → **69Mpps** (no-op同等)


 1. /etc/default/grub を編集
  GRUB_CMDLINE_LINUX_DEFAULT="mitigations=off"

  2. GRUB設定を再生成
  sudo update-grub

  3. 再起動
  sudo reboot

  4. 再起動後に確認
  cat /proc/cmdline                                    # mitigations=off が含まれること
  cat /sys/devices/system/cpu/vulnerabilities/spectre_v2  # "Vulnerable" になること


● 原因見つけました。

  72.58%  native_queued_spin_lock_slowpath
    └→ cache_tag_flush_range_np
        └→ intel_iommu_iotlb_sync_map
            └→ iommu_dma_map_page
                └→ __ice_xmit_xdp_ring

  iceドライバじゃない。Intel IOMMU (VT-d)
  のspinlock。全パケットのDMAマッピングでIOMMUのTLBフラッシュが走り、そこのロックで72%スピンしている。

  修正は簡単。ブートパラメータに追加:

  iommu=pt

  iommu=pt (passthrough) にすると、DMAアドレス変換をバイパスしてロック競合がなくなります。既に mitigations=off
  を入れてるので、GRUBに追記するだけ:

  GRUB_CMDLINE_LINUX_DEFAULT="mitigations=off iommu=pt"

  sudo sed -i 's/mitigations=off/mitigations=off iommu=pt/' /etc/default/grub
  sudo update-grub
  sudo reboot

  これで劇的に変わるはず。virtio-netでIOMMUが問題にならなかったのは、virtioがIOMMUバイパスするか、VM環境でVT-dが効いてなかったから。
  実機のiceでは全パケットがIOMMU経由になってた。



sudo ./out/bin/xdperf run --plugin=simpleudp.go --device=enp138s0f0np0 --plugin-path="./out/bin" --count 1 --parallelism 1 --infinite --batch-size 256 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200, "is_arp_resolve":false}'


sudo ./out/bin/xdperf run --plugin=simpleudp.go --device=enp138s0f0np0 --plugin-path="./out/bin" --count 50 --parallelism 50 --infinite --batch-size 64 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 64, "is_arp_resolve":false}'
