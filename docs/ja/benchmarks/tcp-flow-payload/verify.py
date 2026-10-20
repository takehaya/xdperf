#!/usr/bin/env python3
"""Recompute paired means and t(5) confidence intervals from external raw and derived rows."""
import csv
import json
import math
from pathlib import Path
import sys
import statistics

root = Path(__file__).resolve().parent
data = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('out/mixbench/main')
rows = list(csv.DictReader((data / 'derived.csv').open()))
raw = list(csv.DictReader((data / 'raw.csv').open()))
assert len(raw) == len(rows)
for source, derived in zip(raw, rows):
    assert all(derived[key] == value for key, value in source.items())
summary = list(csv.DictReader((root / 'summary.csv').open()))
schedule = json.loads((data / 'schedule.json').read_text())
keys = [(int(r['block']), r['mode'], int(r['workers']), r['version']) for r in rows]
assert len(keys) == len(set(keys)) == 120
assert keys == [tuple(x) for x in schedule]
for i in range(0, len(keys), 2):
    left, right = keys[i:i + 2]
    assert left[:3] == right[:3] and {left[3], right[3]} == {'base', 'head'}

assert {r['mode'] for r in rows} == {'packet', 'mixed31', 'template', 'vxlan', 'geneve'}
assert {int(r['workers']) for r in rows} == {1, 4}
metrics = {'packet_pps', 'tcp_segments_s', 'tcp_goodput_mbps', 'startup_s',
           'base_load_s', 'after_plugin_s', 'tx_rtx', 'tcp_tx_ratio',
           'packet_errors', 'dispatch_errors'}
expected = {(mode, str(workers), metric)
            for mode in ('packet', 'mixed31', 'template', 'vxlan', 'geneve')
            for workers in (1, 4)
            for metric in metrics | ({'packet_steady_pps'} if mode == 'packet' else set())}
actual = [(s['mode'], s['workers'], s['metric']) for s in summary]
assert len(actual) == len(set(actual)) and set(actual) == expected
assert all(int(s['n']) == int(s['pairs']) == 6 for s in summary)
for row in rows:
    assert int(row['packet_errors']) == int(row['dispatch_errors']) == 0
    if row['mode'] != 'packet':
        assert int(row['bytes_acked']) == int(row['sink_bytes'])
        trial = data / f"b{int(row['block']):02d}-{row['mode']}-w{row['workers']}-{row['version']}"
        flows = list(csv.DictReader((trial / 'flows.csv').open()))
        sink = json.loads((trial / 'sink.log').read_text().splitlines()[-1])
        assert len(flows) == sink['accepted'] == sink['closed'] == 4
        assert all(flow['state'] == 'done' for flow in flows)
        assert sum(int(flow['bytes_acked']) for flow in flows) == int(row['bytes_acked']) == sink['bytes']
        assert sum(int(flow['tx_rtx']) for flow in flows) == int(row['tx_rtx'])
        final_lines = [line for line in (trial / 'tx.log').read_text().splitlines() if 'tcp final statistics' in line]
        assert len(final_lines) == 1
        counters = json.loads(final_lines[0][final_lines[0].index('{'):])
        assert counters['done'] == 4 and counters['bytes_acked'] == sink['bytes']
        assert all(counters[key] == 0 for key in ('build_errors', 'failed', 'aborted', 'retransmit_giveups', 'fin_wait2_timeouts'))




def ci(values):
    assert len(values) == 6
    mean = statistics.mean(values)
    half = 2.570581835636305 * statistics.stdev(values) / math.sqrt(6)
    return mean, mean - half, mean + half


for s in summary:
    metric = s['metric']
    group = [r for r in rows if r['mode'] == s['mode'] and r['workers'] == s['workers']]
    base = {int(r['block']): float(r[metric]) for r in group if r['version'] == 'base'}
    head = {int(r['block']): float(r[metric]) for r in group if r['version'] == 'head'}
    assert base.keys() == head.keys() == set(range(1, 7))
    checks = {'base_mean': statistics.mean(base.values())}
    for names, values in [
        (('head_mean', 'head_ci_low', 'head_ci_high'), list(head.values())),
        (('delta_mean', 'delta_ci_low', 'delta_ci_high'), [head[b] - base[b] for b in base]),
    ]:
        checks.update(zip(names, ci(values)))
    if all(base.values()):
        checks.update(zip(('pct_mean', 'pct_ci_low', 'pct_ci_high'),
                          ci([100 * (head[b] / base[b] - 1) for b in base])))
    for key, value in checks.items():
        assert math.isclose(float(s[key]), value, rel_tol=1e-9, abs_tol=1e-9), (s, key, value)
print('Verified 120 trials, paired means, and two-sided t(5) 95% CIs.')
