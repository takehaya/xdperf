# simpleudp-scx

[simpleudp](../simpleudp/) と同じ UDP フローを、`--scx` (sched_ext による
worker CPU 隔離) を有効にして送信するシナリオ。

検証内容:

- パケットカウンタの一致 (simpleudp と同じ合否判定)
- 送信ログに sched_ext スケジューラの attach 証跡 (`ops=xdperf`) と
  クリーンな detach (`default scheduler restored`) があること

## 前提

- カーネル 6.13+ かつ `CONFIG_SCHED_EXT=y` (満たさない場合は SKIP / exit 3)
- 他の sched_ext スケジューラ (scx_lavd 等) が動作していないこと (SKIP)
- CPU 2 個以上 (worker + housekeeping)

GitHub ホストランナーのカーネルは sched_ext 未対応のため CI では SKIP になる。
実走させる場合は `scripts/scx_kernel/build.sh` でテストカーネルをビルドし、
vimto で実行する (`.github/workflows/scx_load_test.yaml` と同じ流れ):

```bash
./scripts/scx_kernel/build.sh
vimto -kernel "$PWD/out/scx-kernel/bzImage" -smp 4 -memory 2G exec -- \
    /bin/bash -c "cd $PWD && ./examples/simpleudp-scx/setup.sh && ./examples/simpleudp-scx/test.sh; rc=\$?; ./examples/simpleudp-scx/teardown.sh; exit \$rc"
```

## 実行

```bash
sudo ./examples/simpleudp-scx/setup.sh
sudo ./examples/simpleudp-scx/test.sh
sudo ./examples/simpleudp-scx/teardown.sh
```
