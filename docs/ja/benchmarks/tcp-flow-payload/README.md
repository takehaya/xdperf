# TCP の追加機能を使わない条件の性能比較を記録する

[段階 4 の測定記録](../../design_tcp_flow_template.md#段階-4-の測定記録) の集計を収録する。
比較元は `9117909`、変更後は `9e9e9d2` で、Timestamps、パターン、フロー別パラメーターを使わない既存経路を比較した。
機能を有効にした場合の性能を示す結果ではない。

[summary.csv](summary.csv) は packet、mixed31、template、VXLAN、GENEVE の各 1/4 worker、6 ブロック、計 120 試行の集計である。
各 8 秒、TCP 4 フロー、MSS 1024、window 32、packet:TCP=3:1、batch 64、pool 128 を使った。
Linux 7.0.0-38-generic、32 vCPU の KVM VM 上の veth 測定であり、実 NIC の結果ではない。
対応差は head - base、対応変化率は各対の 100 * (head / base - 1) の平均である。
両側 95% CI は t 分布の自由度 5、係数 2.570581835636305 を使い、外れ値除外と多重比較補正は行っていない。

生ログ、raw/derived CSV、schedule.json、ビルド情報、バイナリ、測定スクリプトは保存していない。
元の作業ディレクトリは削除済みである。
[verify.py](verify.py) は試行ごとの値から対応差と CI を再計算するコードとして残すが、summary.csv だけでは動作しない。
入力ディレクトリを第 1 引数に取り、raw.csv、derived.csv、schedule.json に加え、各試行の flows.csv、sink.log、tx.log も必要とする。
現在は当時の入力がなく、このリポジトリだけから集計の再検算はできない。
本文と CSV は当時の集計記録として扱う。
