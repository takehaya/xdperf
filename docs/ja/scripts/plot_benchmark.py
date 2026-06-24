#!/usr/bin/env python3
"""benchmark_realnic.md のグラフを生成する。

使い方:
    python3 docs/ja/scripts/plot_benchmark.py

出力:
    docs/ja/imgs/bench_roundtrip.png   (実験2: 片方向 vs 往復 ペイロード長スイープ)
    docs/ja/imgs/bench_rt_cores.png    (実験1: 64B 往復 送信コア数スイープ)

データは benchmark_realnic.md の実測値（実機100G, Intel E810-C, 送受信とも xdperf/XDP）。
受信側カウンタ実測。Gbps は pps から別途算出（本図は pps）。
依存: matplotlib, numpy
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

OUT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "imgs"))
os.makedirs(OUT, exist_ok=True)

# 2 図で共有する系列の色とラベル（線種だけ図ごとに変える）
OW_COLOR = "#1a5fb4"
RT_STYLE = dict(color="#2ec27e", label="round-trip RX (Both mode + echo)")


def wire_mpps(frame_on_wire_bytes):
    """100G のワイヤーレート(Mpps)。preamble+IFG=20B を加算。"""
    return 100e9 / ((frame_on_wire_bytes + 20) * 8) / 1e6


def _save(fig, ax, *, xticks, xticklabels, xlabel, title, ylim, filename):
    """2 図共通の仕上げ（軸目盛・グリッド・凡例・保存）。"""
    ax.set_xticks(xticks)
    ax.set_xticklabels(xticklabels)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("RX Mpps")
    ax.set_ylim(*ylim)
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    path = os.path.join(OUT, filename)
    fig.savefig(path, dpi=110)
    print("saved", path)


def plot_payload_sweep():
    # 実験2: ペイロード長スイープ (送信 par=32, multiflow)
    frame = [64, 128, 256, 512, 1024, 1280, 1500]
    one_way = [116.5, 84.3, 45.3, 23.5, 11.97, 9.62, 8.22]    # 片方向RX (xdperf --recv)
    round_trip = [104.5, 78.9, 45.2, 23.5, 11.97, 9.62, 8.22]  # 往復RX (Both mode + echo)
    xi = np.arange(len(frame))
    wr = [wire_mpps(f) for f in frame]
    wr[0] = wire_mpps(68)  # 64B は xdperf 最小フレーム = on-wire 約68B

    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    ax.plot(xi, one_way, "o-", color=OW_COLOR, label="one-way RX (xdperf)")
    ax.plot(xi, round_trip, "s--", **RT_STYLE)
    ax.plot(xi, wr, ":", color="gray", label="100G wire rate")
    _save(fig, ax, xticks=xi, xticklabels=frame,
          xlabel="frame size (B; 64B = on-wire ~68B)",
          title="Round-trip vs one-way RX (XDP only, par=32)",
          ylim=(0, 155), filename="bench_roundtrip.png")


def plot_core_sweep():
    # 実験1: 64B 往復 送信コア数スイープ (上限32 = 物理コア数)
    cores = [1, 2, 4, 8, 16, 24, 32]
    rt = [5.56, 13.26, 25.07, 46.82, 85.54, 109.09, 104.81]
    ci = np.arange(len(cores))

    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    ax.plot(ci, rt, "s-", **RT_STYLE)
    ax.axhline(116.5, ls="--", color=OW_COLOR, alpha=0.6, label="one-way 64B RX 116.5")
    ax.axhline(142.0, ls=":", color="gray", label="64B wire rate 142 (on-wire 68B)")
    _save(fig, ax, xticks=ci, xticklabels=cores,
          xlabel="sender cores (parallelism)",
          title="64B round-trip: sender cores vs round-trip RX (XDP only)",
          ylim=(0, 160), filename="bench_rt_cores.png")


if __name__ == "__main__":
    plot_payload_sweep()
    plot_core_sweep()
