#!/usr/bin/env python3
"""Render paired startup and throughput estimates from summary.csv."""
import csv
from pathlib import Path

rows = list(csv.DictReader((Path(__file__).resolve().parent / 'summary.csv').open()))
print('| 条件 | worker | 指標 | base 平均 | head 平均 | 対応差平均 [95% CI] | 対応変化率 % [95% CI] |')
print('|---|---:|---|---:|---:|---|---|')
for row in rows:
    metric = row['metric']
    if metric == 'startup_s':
        label, scale = '起動 ms', 1000
    elif row['mode'] == 'packet' and metric == 'packet_steady_pps':
        label, scale = '定常 Mpps', 1e-6
    elif row['mode'] != 'packet' and metric == 'tcp_goodput_mbps':
        label, scale = 'TCP Mbps', 1
    else:
        continue
    def value(key):
        return f"{float(row[key]) * scale:.3f}"
    pct = [f"{float(row[key]):.2f}" for key in ('pct_mean', 'pct_ci_low', 'pct_ci_high')]
    print(f"| {row['mode']} | {row['workers']} | {label} | {value('base_mean')} | "
          f"{value('head_mean')} | {value('delta_mean')} [{value('delta_ci_low')}, "
          f"{value('delta_ci_high')}] | {pct[0]} [{pct[1]}, {pct[2]}] |")
