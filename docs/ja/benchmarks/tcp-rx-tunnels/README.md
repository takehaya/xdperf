# 受信トンネル解析の対応比較

比較元は `ad72a7f`、変更後は `9277b88` とする。
バイナリとプラグインを Go 1.25.5 でビルドし、SHA-256 を保存する。
測定環境は Linux 7.0.0-38-generic、AMD EPYC 7713P を公開する 32 vCPU の KVM VM、Linux veth であり、実 NIC のスループットを示す結果ではない。

既存 mixbench の送受信、タイミング、終了時の照合を継承した。
変更点は全条件で base/head を測ることと、専用の名前空間名を使うことである。
packet 専用、非カプセル化 TCP ひな型、VXLAN、GENEVE の 4 条件を、1/4 worker、6 ブロック、各 8 秒で測定する。
各条件の base/head を隣接させ、ブロック内の条件順と各対の実行順を無作為化する。
混合比は packet:TCP=3:1、TCP は 4 フロー、MSS 1024、window 32 とする。
VXLAN/GENEVE は外側 IPv4/UDP LCO を使う。
統計用 BPF runtime counters は無効とし、測定後に元の設定を復元する。

起動時間はプロセス起動から送信開始ログまでとする。
混合スループットは送信開始から drain 開始までの時間と最終カウンタから求める。
packet 定常 pps は統計ログの最初の 6 区間から求め、終了処理に影響される最終カウンタ pps も残す。
対応差は各ブロックの `head - base`、対応変化率は `100 * (head / base - 1)` の平均である。
両側 95% CI は対応差の標本標準偏差と t 分布（自由度 5、係数 2.570581835636305）で計算する。
多重比較補正や外れ値除外は行わない。

Git に残す測定データは `summary.csv` と検算用の `verify.py`、表を生成する `report.py` だけとする。
結果と解釈は [設計書](../../design_tcp_flow_template.md#段階-3-の測定記録) に記載する。
生データ、実行スクリプト、ビルド情報は Git 管理外の `out/mixbench/` と次の保存先に残した。

```text
/tmp/claude-1000/-home-ubuntu-private-xdperf/925f4640-ff78-496d-acec-28904e958eb9/scratchpad/mixbench/tcp-rx-tunnels/
```

保存先の `main/raw.csv` は全試行、`main/derived.csv` は packet 定常値を追加した行、`main/schedule.json` は実行順である。
`main/environment.json` と各試行の `before.json`、`after.json` は環境を記録する。
各試行のディレクトリにはログ、タイムスタンプ、設定、フロー記録、BPF metadata も残す。
`builds.json` はコミットと実行ファイルの SHA-256、`bytecode.txt` は静的 BPF 命令列の比較を記録する。
`bench.py` と `analyze.py` は測定と再集計に用いたスクリプトである。

再測定時は保存先のスクリプトを専用ディレクトリに置き、`bin/base/` と `bin/head/` に各版の `xdperf`、`xdperf-sink`、`mixed.go.wasm`、`simpleudp.go.wasm` を用意する。
CPU 4〜15 が使用可能で、root、iproute2、iptables、bpftool が必要である。

```sh
# 保存先で再測定する場合
sudo python3 bench.py --output rerun --blocks 6 --duration 8 --stats 0 \
  --modes packet,template,vxlan,geneve --workers 1,4
python3 analyze.py rerun

# リポジトリのルートで保存済みの集計を検算する場合
python3 docs/ja/benchmarks/tcp-rx-tunnels/verify.py out/mixbench/main
python3 docs/ja/benchmarks/tcp-rx-tunnels/report.py
```

## 機能検証

実装コミット `9277b88` に対して `make test`（`go test -v -exec sudo -race ./...`）、`make test-runnable`、`make lint` が成功した。
C WASM プラグインもビルドして integration test を実行した。
最終の既存走査保持とスタック修正を含む状態で全 examples 13 シナリオを再実行し、すべて成功した（`out/rx-tunnels/examples-handoff-final.log`）。

新しい tcp-tunnels は内側 IPv4/IPv6 ごとに gre、gre-key、gretap、ip6gre、ipip/SIT、ip6tnl、srv6、srv6-two、srv6-bare、mpls、gtpu を実行する。
全 22 ケースで、実際の Linux デバイスを対向に 4 フロー完了、77,830 バイトの受信と ACK を照合した。
この環境ではスキップも BPF_PROG_RUN のみによる代替もない。
GTP-U 拡張ヘッダ、最大 8 label、SRH と異種入れ子、不正長、全 byte 境界の切詰めなどは BPF_PROG_RUN で追加検証した。

Linux 6.1/6.6 の CI で一度、parser の合計 stack が 544 バイトとなりロードに失敗した。
`9277b88` で legacy walker のフレームを解放してから extended walker を呼ぶ構成へ修正した。
修正後は [BPF load / data-plane CI](https://github.com/takehaya/xdperf/actions/runs/39294979917) の Linux 6.1、6.6、6.12、6.18、7.0、7.1、7.2-rc2 すべてで成功した。
OCR は 4 名による 4 回のレビューを行い、GTP-U の受信規則、環境依存 E2E の扱い、旧新 walker の境界テスト、集計表の完全性検証を修正し、未解消の指摘はない。
