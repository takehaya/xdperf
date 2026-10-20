# main の文書と実装の対応を点検する

基準は main の `23228c6`（#127）で、#117〜#127 の TCP、混合バリアント、veth、C プラグイン、定義生成を中心に点検した。
CLI は [main.go](../../cmd/xdperf/main.go) と [設定検証](../../pkg/xdperf/config.go)、SDK は [surface.go](../../pkg/guest/surface.go)、混合処理は [mixed.go](../../pkg/xdperf/mixed.go)、[TCP ひな型](../../pkg/xdperf/tcp_template.go)、[トンネル](../../pkg/xdperf/tcp_encap.go)、[フロー別パラメーター](../../pkg/xdperf/tcp_flow_params.go)、BPF は src、examples は各スクリプトを正とした。
変更対象は文書と SDK の説明コメントだけである。
環境変数の設定値が CLI の既定値で上書きされる既存の問題を確認した。
コードは変更せず、末尾に根拠と影響を記す。

## 文書ごとの確認結果を記録する

パスはリポジトリルートを基準とする。
据え置きの測定値は再測定や生データからの再検算を意味しない。

| 文書 | 確認した観点 | 直した点 | 直さなかった点と理由 |
| --- | --- | --- | --- |
| `AGENTS.md` | データフロー、C ファイル、プラグイン、生成ターゲット | 混合 TX/RX、ひな型と拡張入口、RX 診断、mixed.go/vxlan.c、packetdefs の生成器と make ターゲットを追加。環境変数が CLI の既定値で上書きされる現状を明記 | 既存の Go、NUMA、packet の構成は継続して使うため維持。削除済み API やプラグインへの有効な案内はない |
| `CLAUDE.md` | AGENTS の取り込み | 変更なし | AGENTS.md を参照、import しており、アーキテクチャの重複記述はない |
| `README.md` | 利用入口、TCP、ビルド | 混合実行例、TCP フロー CSV、veth キュー、C プラグインビルド、C-to-Go 生成の案内を追加 | 既存の packet/TCP 単独例は現行 CLI と合うため維持 |
| `docs/cli.md` | CLI の全フラグ、既定値、モード別制約 | TCP と混合の表、rx-device/xdp-mode/wasm-cache-dir、C ABI、RX メトリクスを追加。プラグインガイドへの相対リンクを修正 | packet の count/duration/PPS 制約は現行どおり。TCP の例外を明示して残す |
| `docs/ja/mixed_variants.md` | SDK の JSON と利用者向け説明 | 新規追加。kind、重み、TCP base、修正表、Timestamps、パターン、フロー別 IP、トンネル制限、起動と終了を説明 | プラグイン固有の設定名は専用 README に置き、SDK の JSON と区別 |
| `docs/ja/tcp_stream.md` | 単独 TCP と混合の違い、CSV、RX カウンター | シナリオという旧説明を修正。全ゼロ、Timestamps なし、QinQ 非対応の適用範囲を単独 TCP に限定。PPS をイテレーション上限と説明 | CSV 列と 6 種の RX 診断は実装に一致。カウンターを損失と断定しない説明を維持 |
| `docs/ja/design_mixed_variants.md` | 初期設計と現行 API の矛盾 | 単一宛先、Go のみのヘッダ生成、base/params の一律拒否を修正。トンネル RX と実装済み機能を反映 | 重み付き配分、packet 必須、drain と CSV の設計は現行と一致 |
| `docs/ja/design_tcp_flow_template.md` | 段階別 API、マップ、RX、測定資料 | 段階 1〜4 の実装済み状態とフロー別マップ拡張を明示。一時保存先を除き、残る集計と検算の限界へ置き換え | 段階別の当時の検証結果と測定値は履歴として維持。初期の制限には適用段階を明示 |
| `docs/ja/design_mixed_startup.md` | 基底/追加ロード、特殊化、起動測定 | 履歴としての位置付けを明示。削除済み作業領域への保存案内を除去し、3 回の集計 CSV と再検算不能の範囲を記載 | 当時の回帰検出、修正過程、数値は変更していない。再測定は依頼範囲外 |
| `docs/ja/design_xdp_tcp.md` | CLI、状態と構造体、混合拡張 | 古い構造体の複製を現在の役割表と正本への参照に置換。flow サイズ、CLI 既定値、CSV、VLAN、drain/linger、examples 名を修正 | レビュー対応の経緯は記録として維持。単独 TCP と混合の範囲を冒頭で区別 |
| `docs/ja/design_c_to_go_shared_defs.md` | #127 の実装状態、生成器、モジュール境界、参照 | 移行前の調査と実装済みの状態を区別。存在しない実験文書へのリンクを C README に変更。一時ログ参照を残る JSON fixture と検証コードへ変更 | 方式比較と段階 6 の外部 Cilium 未検証は維持。実施していない検証を完了とはしない |
| `docs/ja/src_architecture.md` | src の実ファイル、マップ、tail call | 混合、decap、encap、Timestamp、payload、RX 診断のファイルを追加。共有 TCP マップと PERCPU packet マップを区別し、混合時の強制コピー、3 エントリの checksum tail call と再計算入口を補足 | packet の Diff とチェックサム処理は継続して使用するため維持 |
| `docs/ja/otlp_metrics.md` | 登録条件、カウンターの意味 | xdperf.mixed.rx と reason を追加。既存の packet メトリクスが TCP を含まないことを明示 | Collector の構成例は変更なし。今回の点検では外部サービスの実行確認はしない |
| `docs/ja/tips.md` | NUMA、veth キュー数、警告とカウンター | 単一ノードでも CPU リストは有効と修正。送信側 xmit_errors、CPU 番号によるキュー競合、警告の対向推定を説明。過去ログの位置付けを追加 | 当時の性能値と Cilium の観測値は記録として維持。現在の性能として再確認していない |
| `docs/ja/performance_optimization_plan.md` | 過去の計画と現行実装 | 導入時点の検討記録と明示し、実装済みのキャッシュによる tail call 省略、checksum メタデータ、現在の構成への参照を追加 | 未採用案と過去の数値は設計履歴として維持 |
| `docs/ja/benchmark_realnic.md` | packet コマンド、図と生成スクリプトの存在、veth 案内 | 変更なし | 現行 packet モードと一致。実機の測定値や性能解釈の再評価は今回行わない |
| `docs/ja/benchmarks/mixed-startup/README.md` | 3 回の CSV、verify.py の入力、保存先 | 削除済み領域への案内と実行不能な検算例を除去。必要入力と生ログ未保存を明示 | 集計 CSV と検算スクリプトはそのまま残す。summary だけで CI を再計算できるとはしない |
| `docs/ja/benchmarks/tcp-rx-tunnels/README.md` | 集計、verify/report の役割、保存先 | 一時領域と失われた bench.py/analyze.py の実行案内を除去。report.py による表生成と生データ検算を区別 | 当時の機能検証と測定条件は維持 |
| `docs/ja/benchmarks/tcp-flow-payload/README.md` | summary と verify の利用条件 | 新規追加。比較対象、未使用機能の比較であること、必要な試行ファイルと生ログ未保存を記載 | 数値と検算コードは変更なし |
| `docs/ja/benchmarks/*/*.csv` | データセットの種類と文書の案内 | 数値変更なし | 生データがないため、新しい検算結果として扱わない。過去の集計値を保つ |
| `docs/ja/benchmarks/*/verify.py`、`tcp-rx-tunnels/report.py` | 入力ファイルと集計からの表生成の違い | コード変更なし。README 側で必要入力と限界を説明 | 文書のみの依頼に従い、既定の一時パスや検算処理は変更しない。test-bpf-load の verify.py も当時の raw CSV とテスト一覧が必要で、集計データは未収録 |
| `docs/ja/scripts/plot_benchmark.py`、`docs/ja/imgs/*` | 図の参照、スクリプト内の集計値 | 変更なし | 過去の実機結果の図と生成コード。再生成や測定は不要 |
| `docs/imgs/*`、`docs/xdperf.pdf` | README の参照と PDF の位置付け | 変更なし | ロゴと 2025 年発表資料。PDF はテキストを抽出して確認し、現在のフラグリファレンスとは扱わない |
| `examples/README.md` | 実在シナリオ、キュー設定、UDP/TCP の構成差 | mixed、tcp-template、tcp-vxlan、tcp-tunnels、tcp-payload を追加。VETH_QUEUES と CPU 番号の関係を説明 | 基本 UDP の図と検証方法は引き続き有効 |
| `examples/simpleudp/README.md` | setup/test と環境変数 | 変更なし | COUNT/PPS、プラグイン、判定基準はスクリプトと一致 |
| `examples/simpleudp-vlan/README.md` | VLAN パラメーター | 変更なし | VLAN_ID/PCP と UDP の受信処理は一致 |
| `examples/simpleudp-echo/README.md` | XDP_TX の戻り経路、判定値 | 変更なし | 送信側 attach と ECHO_THRESHOLD の説明は一致 |
| `examples/simpleudp-no-rx-attach/README.md` | XDP/GRO の 2 段階検証 | 変更なし | 対向 NAPI と通常スタックへの配送の区別は一致 |
| `examples/simpleudp-xdp-generic/README.md` | generic attach と GRO | 変更なし | 強制 generic と対向 NAPI 有効化は一致 |
| `examples/simpleudp-split-rx/README.md` | rx-device、DUT 経由の検証 | 変更なし | packet 専用の分離受信例として現行と一致。混合の対応例とは案内しない |
| `examples/srv6/README.md` | 3 モード、フレームサイズ、パラメーター | 変更なし | packet の SRv6 例として一致。TCP ひな型の上限と混同しない |
| `examples/tcpstream/README.md` | 単独 TCP、レスポンダ、veth | CPU 番号をキュー数で割った余りによる競合条件を補足 | フロー CSV と混合の参照、損失注入、VLAN の説明は現行と一致 |
| `examples/tcp-template/README.md` | tcp_base、固定オプション、6 ケース | 変更なし | IPv4/IPv6、VLAN/QinQ、完了バイト数は実装と一致 |
| `examples/tcp-vxlan/README.md` | TX と RX の対応段階 | VXLAN/GENEVE 以外の RX を後続扱いする記述を修正 | zero/LCO の 6 ケースと UDP source port の説明は一致 |
| `examples/tcp-tunnels/README.md` | Linux トンネル、非対称応答、skip | 変更なし | 形式、encaplimit none、ケース選択、SKIP 条件はスクリプトと一致 |
| `examples/tcp-payload/README.md` | timestamps、pattern、flow_variable_params | 変更なし | 設定名、内側送信元 IP の制限、IPv4/IPv6 の検査は一致 |
| `examples/otlp-metrics/README.md` | 管理経路と Collector、変数 | 変更なし | 計測と管理の経路分離、カウンターの照合は現行と一致 |
| `plugins/README.md` | SDK、Go/TinyGo/C ABI、プラグイン一覧 | goshim とバッファ ABI を区別。mixed/C VXLAN、定義生成、混合制約を追加。run のない旧コマンドを修正 | simpleudp の設定表は現行の設定に合うため維持 |
| `plugins/mixed.go/README.md` | サンプル設定と SDK フィールドの対応 | 新規追加。全設定、IPv4 UDP、IPv6 TCP の指定、終了条件を説明 | SDK を拡張せず、実際にサンプルが返す 4 フローを説明 |
| `plugins/vxlan.c/README.md` | ABI、ビルド、共有ヘッダ | Go の生成型と生成ターゲットを案内 | C の設定と機能は Go 版と異なるため同じ設定表に統合しない |
| `plugins/vxlan.go/README.md` | #127 の builder 移行、設定 | 生成 codec と正本、通常ビルドと再生成の違いを追記 | VLAN、IMIX、L2-only、sweep、UDP zero は維持 |
| `plugins/gtpv1u.go/README.md` | 設定、PSC、packet バリアント | 変更なし | packet 用 GTP-U として現行に一致。TCP の TX S/PN 拒否とは適用対象が違う |
| `plugins/srv6.go/README.md` | モード、segment、可変範囲、チェックサム | 変更なし | packet プラグインの機能と一致。混合 TCP の上限は別に説明 |
| `plugins/test_e2e_variety.go/README.md` | プロトコル一覧と呼び出し | 変更なし | raw TCP テストフレームと stateful tcp_flow を区別でき、既存例は有効 |
| `pkg/guest/surface.go` | 公開型の doc コメント | kind、重み、TCP base、Timestamps、pattern、フロー別 params、修正表と制約を補足。古い応答先名を修正 | 型、JSON tag、実行処理は変更しない |
| `pkg/guest/api.go`、`layers.go`、`memutils.go`、`goshim/*.go` | host import、バッファ、checksum helper の説明 | 変更なし | コメントは処理と一致。今回の新しい混合契約は surface.go に集約 |
| `pkg/guest/packetdefs/vxlan/*` | 生成型と helper の説明 | 変更なし | 生成物は手編集せず、C/manifest を正とする。helper の VNI 検査と ABI の説明は一致 |

## 保存資料と検証の限界を示す

削除済み worktree の生ログや実行ファイルを、利用可能な保存先として案内していた記述を除いた。
#121/#123 の比較は本文の表だけがリポジトリに残り、その後の起動時間、RX トンネル、ペイロードの集計 CSV は別の測定である。
リポジトリ外の一時ディレクトリは文書から参照しない。
検算コードは残すが、当時の入力がないものは現在のリポジトリだけでは動作しないと記した。

今回、性能測定とローカルの BPF/E2E テストは実行していない。
ローカル検証は make lint と、コミットしないスクリプトによる Markdown の相対リンク、見出し、ソースやサンプルのパス確認を行う。
make lint の初回と 2 回目は一部フックのシェル起動が operation not permitted となった。
GOMAXPROCS=1 を付けた再実行では全フックが成功した。
CI と OCR/Copilot の結果は PR に記録する。

## コード側の既存の問題を報告する

[ParseArgs](../../cmd/xdperf/main.go) は envconfig.Process で XDPERF_ 環境変数を読み込んだ後、通常フラグに対応する設定を ctx.String、ctx.Bool、ctx.Int 等で無条件に上書きする。
CLI フラグ側には EnvVar の指定もないため、例えば XDPERF_DEVICE や XDPERF_PPS だけを指定しても、フラグの既定値で置き換えられる。
AGENTS.md の環境変数も設定に使えるという一般的な説明を修正し、現状では CLI フラグを使うよう記した。
この問題はコードの変更が必要なため、今回の文書同期では修正しない。
静的なコード照合による確認であり、追加の実行テストは行っていない。
