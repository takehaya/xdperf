# sched_ext スケジューラ (--scx) 設計

`--scx` は、sched_ext (eBPF CPU スケジューラ、kernel 6.12+) を使って
**送信中だけ worker CPU を xdperf 専有にする** opt-in 機能。実装は
`src/scx_prog.c` (BPF 側) と `pkg/scx` (Go ローダ) に分かれる。

## 目的と非目的

目的:

- worker CPU から他タスクを排除し、ペーシングの裾 (batch wakeup error の
  p99/max、秒間 PPS の変動係数) を安定させる
- `isolcpus` のような再起動を伴うブート設定なしで、動的に隔離を得る
- `--sched-policy fifo` の落とし穴 (RT スロットリングによる周期停止、
  100% busy 時の percpu kthread 飢餓 → RCU stall) を避ける

非目的:

- ピーク PPS の向上。アイドルな専用機ではワーカーはもともと走り続けて
  おり、スケジューラを替えても速くはならない。効くのは他負荷が同居する
  環境での「安定化」
- IRQ/softirq の制御。割込みはどのスケジューラでも管轄外なので、NIC IRQ
  の worker CPU 直撃は `xdperf probe` の環境チェックと IRQ affinity 設定で
  別途対処する

## 方式: full-switch

sched_ext には「SCHED_EXT ポリシーのタスクだけを管理する」partial モード
(`SCX_OPS_SWITCH_PARTIAL`) もあるが、それでは**他タスクを worker CPU から
動かせない** (他タスクは既定スケジューラ管理のまま全 CPU に載る)。隔離が
目的なので、attach 中は通常クラスの全タスクを本スケジューラが管理する
full-switch を採る。

RT / DEADLINE / stop クラスは sched_ext の上位に居続ける (migration
スレッド等はそもそも管轄外)。`--sched-policy` と併用禁止なのはこのため:
FIFO にした worker は RT クラスに抜けてしまい、このスケジューラの管理外で
「何を測っているのか」が黙って変わる。

## タスク分類

enqueue / select_cpu のたびに O(1) で分類する (`src/scx_prog.c`):

| 分類 | 判定 | 扱い |
|------|------|------|
| WORKER | `p->tgid == xdperf_tgid` かつ `worker_tids[p->pid]` にヒット | 割当 CPU の local DSQ、実質無限 slice。wakeup 時は `SCX_ENQ_PREEMPT` |
| PINNED | worker CPU 以外に走れる CPU がない (percpu kthread 等) | その CPU の local DSQ、**20µs slice + PREEMPT** |
| OTHER | それ以外すべて | SHARED_DSQ (グローバル FIFO)、既定 20ms slice |

- WORKER 判定が tgid も見るのは TID 再利用対策。worker スレッドの死後に
  別プロセスが同じ TID を得ても worker 待遇を継がせない。tgid はロード時に
  const (`xdperf_tgid`) として注入する。
- PINNED の 20µs + PREEMPT が **watchdog 安全性の要**。percpu kthread を
  飢餓させると sched_ext の stall watchdog (既定 30 秒) がスケジューラを
  強制排除し、計測全体が無効になる。「有界の µs 割込みを受け入れて、
  排除ゼロを保証する」トレードオフ。
- WORKER の PREEMPT を wakeup 時 (`SCX_ENQ_WAKEUP`) に限るのは、preempt
  された worker の再 enqueue で PINNED を preempt し返すライブロックを
  避けるため。20µs 上限で worker はすぐ CPU を取り戻す。

## DSQ 構成と隔離の不変条件

```
worker CPU (例 2,3):  [local DSQ] ← WORKER (INF) / PINNED (20µs, PREEMPT) のみ
others CPU (例 0,1):  [local DSQ] ← dispatch 時に [SHARED_DSQ] から補充
                       [SHARED_DSQ] ← OTHER 全タスク
```

隔離は次の 2 つの不変条件で成り立つ:

1. **select_cpu が OTHER に worker CPU を返さない** — prev_cpu 優先で
   others から選ぶ。pinned タスク (nr_cpus_allowed == 1) はカーネルが
   select_cpu 自体をスキップするので、worker の配置は enqueue 側で行う
2. **worker CPU の dispatch は SHARED_DSQ を引かない** — worker が
   ticker 待ちで寝ていても worker CPU は空けたまま。復帰の即応性を
   スループットより優先する

## ライフサイクル (Go 側)

```
runTXPacket:
  worker 全員が pin + TID 報告 (二相起動バリア)
    ↓ ここが唯一の attach 点
  scx.Attach:
    Supported()            … sysfs + カーネル BTF に scx_bpf_dsq_insert
    先客チェック           … state != disabled なら明確なエラー (EBUSY 相当)
    LoadScx + const 注入   … tgid / worker_cpu_mask
    worker_tids へ Put     … attach 前に全登録 (未登録 worker は自 CPU を
                             奪われるため、順序が正しさの条件)
    link.AttachStructOps   … BPF link ベース
    sysfs 検証             … state==enabled && root/ops==xdperf
    ↓
  close(start) → TX 開始
  (1s ごとに CheckHealth: watchdog 排除を検出したら run を失敗させる)
    ↓
  cancel → 全 worker 退出 → Manager.Close (link close → 既定スケジューラ復帰)
  → 最終統計
```

- **link ベース**なので、プロセスが SIGKILL や panic で死んでも fd 解放で
  カーネルが自動 detach し、既定スケジューラに戻る。システムを固める
  リスクを構造的に避けている (それでも残るのが watchdog で、これは
  「ポリシーのバグで誰かが 30 秒走れない」ときの最終安全網)。
- attach 失敗は **hard abort**。`--scx` は明示された計測条件であり、黙って
  非隔離で走ると結果の解釈を壊す。
- 排除/detach の区別は `ops.exit` が書く exit record (`exit_info` map) で
  行う。`SCX_EXIT_ERROR_STALL` = watchdog 排除。

## 前提条件とガード

| 条件 | 実装 |
|------|------|
| kernel 6.13+ (`scx_bpf_dsq_insert` 系 kfunc) | `scx.Supported()` が sysfs + カーネル BTF で判定。6.12 は「present but too old」と区別してエラー |
| `CONFIG_SCHED_EXT=y` | 同上 (uname 比較はディストロ backport / CONFIG 無効で両方向に嘘をつくため使わない) |
| 他の scx スケジューラ不在 | attach 前に `root/ops` を確認し名前付きでエラー |
| housekeeping CPU ≥ 1 | `NewXdperf` で `len(workers) < オンライン CPU 数` を強制。全 CPU を worker にすると OTHER が走れず watchdog 排除一直線 |
| 送信モード限定 | RX は softirq 駆動で worker スレッドがないため |

## ヘッダ戦略 (vmlinux.h を持ち込まない)

xdperf の BPF ビルドは UAPI ヘッダのみで vmlinux.h を持たない。sched_ext が
必要とするカーネル内部型は `src/scx_kernel_defs.h` に**手書きの部分定義 +
`preserve_access_index`** で宣言し、CO-RE が実行カーネルの BTF に対して
フィールドオフセットを再配置する。ハマりどころは 3 つ (実装時に全部踏んだ):

1. `struct sched_ext_ops` は**使うメンバだけの部分定義でよい**。ローダ
   (takehaya/ebpf フォークの struct_ops 対応) がメンバ名でカーネル構造体と
   突き合わせてオフセット変換する
2. kfunc 引数の `struct cpumask` は**前方宣言では不可** (BTF kind Fwd は
   型照合で拒否される)。ダミーの 1 フィールド定義を置く
3. `scx_exit_info.kind` は **enum として宣言する** (カーネル側が enum の
   ため、int だと CO-RE のフィールド照合が失敗して命令が poison される)

DSQ id エンコーディングや enq フラグ等の定数は文書化された ABI
(Documentation/scheduler/sched-ext.rst) なので #define で持つ。

## テスト戦略

- `pkg/scx/scx_test.go` — load (verifier) / attach→detach 往復 / バリデー
  ション。sched_ext がないカーネルでは self-skip するので、既存の vimto
  マトリクス (6.1〜7.1) と 6.8 開発機でも緑のまま
- upstream の ci-kernels は全レグ CONFIG_SCHED_EXT 無効のため、
  `scripts/scx_kernel/build.sh` で **ci-kernels の config + SCHED_CLASS_EXT
  + VETH** のテストカーネル (6.18.36) をビルドし、
  `.github/workflows/scx_load_test.yaml` が vimto で実走する (bzImage は
  config ハッシュでキャッシュ)
- E2E は `examples/simpleudp-scx/`。パケットカウンタに加えて、送信ログの
  attach 証跡 (`ops=xdperf`) とクリーン detach を別軸で assert する

## 既知の限界と将来課題

- **IRQ/softirq には効かない** (前述)。probe の環境チェックで可視化まで
- OTHER はグローバル FIFO 1 本で、公平性・キャッシュ局所性は最適化して
  いない (目的外)。多ソケット機で問題になるなら NUMA ごとの SHARED_DSQ
  分割が次の一手
- `confined_to_worker_cpus()` は最悪 O(nr_cpus) の線形走査 (通常タスクは
  最初の非 worker CPU で即帰る)。task_local storage による分類キャッシュは
  複雑さに見合わなかったため v1 では見送り
- 対応上限 1024 CPU (`MAX_CPUS`)。超過分の CPU は others 扱いに安全側で
  倒れる
- kfunc 名は 6.13+ 固定。6.12 対応 (旧名 compat) は需要が出たら弱シンボル
  分岐で追加可能
