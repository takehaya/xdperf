# AGENTS.md

このファイルは、AI コーディングエージェント (Claude Code / Codex / Cursor / Aider 等) がこのリポジトリで作業する際の共通ガイダンスです。Claude Code 固有の設定は [CLAUDE.md](CLAUDE.md) を参照してください。

**回答・コミットメッセージ以外のやり取りは基本的に日本語で行ってください。**

## プロジェクト概要

XDPerfは、XDP (eXpress Data Path) を活用したカーネルレベルのパケット処理による高性能ネットワークトラフィックジェネレータです。アプリケーション層にGo、カーネルネットワーキングにeBPF/XDP Cプログラム、拡張可能なパケット生成にWASMベースのプラグイン (wazero経由) を組み合わせています。単一バイナリで、クライアント (送信) とサーバー (受信) の2モードを提供します。

## ビルド・開発コマンド

```bash
make build              # バイナリ (out/bin/xdperf) + WASMプラグインをビルド
make build-plugins      # WASMプラグインのみビルド (TinyGoとGoの両バリアント)
make bpf-gen            # Docker経由でeBPFオブジェクトを再生成 (pkg/coreelf/elf.goのgo generateを実行)
make test               # 全テスト実行: go test -v -exec sudo -race ./...
make test-runnable      # バイナリがパニックせず初期化できることを検証
make examples           # vethベースのend-to-end exampleシナリオを一括実行 (examples/, sudo必要)
make lint               # lefthookによるpre-commitチェック (golangci-lint, clang-format, yamllint等)
make install-dev-tools  # 開発依存パッケージのインストール
make install-build-tools # ビルドツールのインストール (TinyGo等)
make install-lint-tools # Lintツールのインストール
```

テストには**sudo**が必要 (eBPF/ネットワーク操作のため)。単一テストの実行:
```bash
go test -v -exec sudo -race ./pkg/xdperf/ -run TestName
```

## アーキテクチャ

### データフロー

```
CLI (cmd/xdperf/main.go) → 設定パース → Xdperf初期化
  ├── クライアント:
  │   WASMプラグイン読込 → GeneratorProcessResponse取得
  │   ├── Variableモード: ベースパケット + Diff生成 → BPFマップ書込
  │   └── Rawモード: 生パケットをラウンドロビンDiffエントリに変換
  │   → NUMA考慮でworker CPUを選択 (--cpu-mode) → eBPFアタッチ → XDP経由でTX
  └── サーバー: eBPF読込 → 受信、オプションでswap応答

(--tcp 指定時) プラグインを使わず Go がテンプレートフレームを生成 → tcp_cfg/tcp_flow マップ初期化
  → xdp_rx_tcp を attach → xdp_tx_tcp を live frames で駆動 (SYN/データ/FIN/再送) → 相手の ACK を xdp_rx_tcp が処理

(--tcp-server 指定時) tcp_srv_cfg マップ初期化 → xdp_rx_tcp_server を attach (worker 無し)
  → SYN/データ/FIN に XDP_TX で応答、フロー状態は tcp_srv_flow_map (LRU_HASH) → Go のスイーパが古いエントリを回収

(共通・オプション) --otlp-endpoint 指定時: TX/RX統計とNICカウンタをOTLP/gRPCでpush (pkg/telemetry)
```

### 主要パッケージ

- **cmd/xdperf/** — urfave/cliを使用したCLIエントリポイント。`run` (トラフィック生成/受信) と `probe` (XDP機能検出) の2コマンド。
- **cmd/xdperf-sink/** — TCP/UDP を受けてコネクション数・バイト数を数える小さなシンク。`--tcp` モードの対向や、Kubernetes 上のバックエンド Pod として使う。veth 向けに pass-through XDP を attach する `-xdp-pass-dev` を持つ。
- **pkg/xdperf/** — コアロジック: `Xdperf`構造体がライフサイクル全体を管理。設定バリデーション、eBPFアタッチ、Diff生成、PPSレート制限、統計収集。
  - `generator.go` — Diffベースパケット生成のコア。プラグインからの`PacketVariantSet`をBPF用の`DiffEntry`に変換。Sequential/Mixedの2つのバリアント選択モード、重み付き分配をサポート。
  - `bpf.go` — BPFマップ初期化 (`initBasePacketMaps`, `initDiffMap`, `initChecksumMetaMaps`, `initPktStateMap`)。エントリをCPUごとに分配。
  - `stats.go` — リアルタイム統計表示。diff_errorsとchecksum_errorsの追跡を含む。
  - `tcp.go` — TCP ストリームモード (`--tcp`)。XDP だけで TCP クライアントを実装する (SYN/データ/再送/FIN)。テンプレート生成、`tcp_*` マップ初期化、worker 駆動、統計。設計は [docs/ja/design_xdp_tcp.md](docs/ja/design_xdp_tcp.md)、使い方は [docs/ja/tcp_stream.md](docs/ja/tcp_stream.md)。
  - `tcp_server.go` — XDP TCP レスポンダ (`--tcp-server`)。UDP の `--swap-resp` の TCP 版で、待ち受けアドレスの解釈、`tcp_srv_cfg` 初期化、統計、古い LAST_ACK / SYN_RCVD エントリを回収するスイーパ。設計は design_xdp_tcp.md の 12 節。
  - `metrics.go` — OTLPメトリクス送信の計装。`ObservableCounter` のコールバックでBPF統計マップとNIC sysfsカウンタを累積値として読む (stdout表示系とは独立)。
- **pkg/numa/** — NUMA対応のworker CPU選択 (`--cpu-mode`)。`DetectTopology`/`DetectNICNode`でNICのNUMAノードを検出し、`SelectCPUs`/`ParseCPUMode`/`ParseCPUList`で`auto`/`local`/`balanced`/`node:<N>`/CPUリストを解決。マルチソケット機でNICローカルノードにworkerを寄せ、クロスノードメモリアクセスを削減する。
- **pkg/coreelf/** — cilium/ebpfによるeBPFオブジェクト読込。`go:generate`ディレクティブで`bpf2go`を実行し`src/xdp_prog.c`をコンパイル。`ReadCollection()`がdiff_mapサイズを動的に調整。
- **pkg/plugin/** — wazeroランタイムによるWASMプラグインマネージャ。`.wasm`バイナリを読込、ホスト関数 (ログ、メトリクス、ARP解決) を公開、プラグインライフサイクル (init → process → cleanup) を管理。ホスト・ゲスト間はJSONベースで通信。
- **pkg/guest/** — WASMプラグインがインポートするSDK。`PacketVariantSet`、`PacketVariant`、`ChecksumSpec`、`VariableParams`等の型を提供。プラグインは`//go:wasmexport`で`plugin_init`、`plugin_process`、`plugin_cleanup`をエクスポートする必要あり。
- **pkg/probe/** — ネットワークデバイスごとのXDP機能検出 (native, generic, offloadモード)。
- **pkg/telemetry/** — OTLP/gRPC pushによるメトリクス送信 (`--otlp-endpoint` 指定時のみ有効)。otel SDK / gRPC依存をこのパッケージに閉じ込め、MeterProviderの組み立てとshutdown (最終フラッシュ、5sタイムアウト) を担当。使い方は [docs/ja/otlp_metrics.md](docs/ja/otlp_metrics.md) を参照。
- **pkg/logger/** — zapベースの構造化ロギング。

### Diffベースパケット生成 (コアメカニズム)

全パケットをコピーする代わりに、ベースパケット + 差分 (Diff) のみをBPFに渡すメモリ効率の高い方式:

1. **プラグイン** が `PacketVariantSet` を返す (ベースパケット + 可変パラメータ + チェックサム仕様)
2. **generator.go** がGoホスト側で全バリエーションを事前計算し、コンパクトな `DiffEntry` に変換
3. **BPFマップ** に書込:
   - `base_packet_map` — PERCPU_ARRAY、バリアントごとのベースパケット (最大16)
   - `diff_map` — PERCPU_ARRAY、事前計算されたDiffエントリ (最大131072)
   - `checksum_meta_map` — PERCPU_ARRAY、チェックサム再計算のメタデータ
   - `pkt_state_map` — PERCPU_ARRAY、CPUごとのラウンドロビン状態
4. **XDPプログラム** (`xdp_tx`) がDiffをベースパケットに適用し送信、`xdp_tx_checksum`にtail callしてチェックサム再計算

### eBPF/XDPレイヤー

Cソースは`src/`に配置:
- `xdp_prog.c` — メインXDPプログラム (`xdp_tx`, `xdp_tx_checksum`)。tail callでBPF verifierの命令数制限を回避。
- `xdp_prog.h` — XDPプログラム共通の定義・マップ宣言。
- `xdp_packet.h` — データ構造定義 (`base_packet`, `diff_entry`, `diff_value`, `checksum_meta`, `pkt_state`)
- `xdp_checksum.h` — IPv4/IPv6/TCP/UDP/ICMPv6チェックサム計算。`bpf_loop`とsafeコールバックでverifier制約を回避。
- `xdp_utils.h` — ユーティリティマクロ
- `xdp_tcp.h` — TCP ストリームモードのデータ構造・マップと `xdp_tx_tcp` / `xdp_rx_tcp` プログラム。フロー状態は `tcp_flow_map` (ARRAY + `bpf_spin_lock`) に置き、TX/RX 間で共有する。受信フレームをその場で応答に書き換える `tcp_reply_inplace` もここ (レスポンダと共有)。
- `xdp_tcp_server.h` — XDP TCP レスポンダ `xdp_rx_tcp_server` (`--tcp-server`)。フロー状態は `tcp_srv_flow_map` (LRU_HASH、相手の IP とポートがキー、lock 無し)。

コンパイルはDocker (`Dockerfile.bpf`) 経由でclang → bpf2go → `pkg/coreelf/bpf_bpf{el,eb}.go`を生成。Cソース変更後: `make bpf-gen`。

> **パケットキャプチャについて:** `xdperf run` はXDPで送信し、自身ではpcapを書き出さない。生成トラフィックのキャプチャは、非侵襲にアタッチでき内側ヘッダ (GTP-U/VXLAN/MPLS/SRv6等) まで辿れる [xdp-ninja](https://github.com/takehaya/xdp-ninja) を使う。旧来の in-tree な xdpcap フックはホットパスから撤去済み。

### プラグインシステム

WASMプラグインがパケットテンプレートを生成。`plugins/`にリファレンス実装:
- `simpleudp.tinygo/` — TinyGoでビルド (`tinygo build -target=wasip1 -buildmode=c-shared`)
- `simpleudp.go/` — Goでビルド (`GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared`)
- `imixudp.go/` — IMIXトラフィックパターン
- `gtpv1u.go/` — GTP-U (5G/4G) トラフィック。外側UDP/GTP-Uヘッダ + 内側IP/UDPを生成し、内側ポートをスイープ可能。
- `vxlan.go/` — VXLAN (RFC 7348) トラフィック。外側UDP(4789)/VXLANヘッダ + 内側Ethernetフレーム(IPv4/UDP)を生成し、VNI・内側ポート・内側IP・外側ポートをスイープ可能。任意で外側802.1Q VLANタグ(vlan_id、不要なら0で省略)。外側UDPチェックサムは0固定。
- `srv6.go/` — SRv6 (RFC 8754) トラフィック。外側 IPv6 + SRH を生成し、`mode` で内側を選択 (`l3vpn_ipv4`: IPv4/UDP、`l2vpn_eth`: Ethernet+IPv4/UDP、`ipv6`: IPv6/UDP)。セグメントリスト可変 (1〜127)、flow label・SRHタグ・内側ポート・内側IPをスイープ可能。外側 IPv6 にチェックサムはなく、内側チェックサムのみ再計算。
- `test_e2e_variety.go/` — 全プロトコルE2Eテスト (IPv4/IPv6/VLAN/QinQ/ICMP/TCP/ARP/EAPOL/LLDP/SRv6/MPLS)

プラグインは `GeneratorProcessResponse` を返す。2つのテンプレートタイプ:
- **Raw**: 生パケットバイト列のリスト (ラウンドロビンで送信)
- **Variable**: `PacketVariantSet` — ベースパケット + `VariableParams` (バイトオフセット/範囲/パターン) + `ChecksumSpec`。重み付きSequential/Mixed選択。

## コード規約

- **コミットメッセージ:** Conventional Commits準拠 (feat/fix/docs/chore/perf等)
- **Go:** lefthook経由のgolangci-lint
- **C/Hファイル:** clang-formatで整形
- **設定:** CLIフラグ + 環境変数 (XDPERF_プレフィックス、envconfig経由)
- **Goバージョン:** 1.25.5 (go.modで指定)

<!-- OCR:START -->
## Open Code Review Instructions

These instructions are for AI assistants handling code review in this project.

Always open `.ocr/skills/SKILL.md` when the request:
- Asks for code review, PR review, or feedback on changes
- Mentions "review my code" or similar phrases
- Wants multi-perspective analysis of code quality
- Asks to map, organize, or navigate a large changeset

Use `.ocr/skills/SKILL.md` to learn:
- How to run the 8-phase review workflow
- How to generate a Code Review Map for large changesets
- Available reviewer personas and their focus areas
- Session management and output format

Keep this managed block so `ocr init` can refresh the instructions.
<!-- OCR:END -->
