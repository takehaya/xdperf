#!/usr/bin/env python3
"""Recompute paired means and Student t confidence intervals from saved values."""

import csv
import json
import math
from pathlib import Path
import statistics
import sys

T_975_DF5 = 2.570581835636305


def interval(values):
    assert len(values) == 6
    mean = statistics.mean(values)
    half_width = T_975_DF5 * statistics.stdev(values) / math.sqrt(6)
    return mean, mean - half_width, mean + half_width


def check(actual, expected):
    assert math.isclose(float(actual), expected, rel_tol=1e-10, abs_tol=1e-10), (
        actual, expected
    )


def verify(directory):
    with (directory / "derived.csv").open() as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 96
    with (directory / "raw.csv").open() as stream:
        raw = list(csv.DictReader(stream))
    assert len(raw) == len(rows)
    assert all(row[key] == value for original, row in zip(raw, rows)
               for key, value in original.items())
    assert all(int(row[key]) == 0 for row in rows for key in (
        "packet_errors", "dispatch_errors", "tx_rtx"
    ))
    schedule = json.loads((directory / "schedule.json").read_text())
    assert [[int(row["block"]), row["mode"], int(row["workers"]), row["version"]]
            for row in rows] == schedule
    with (directory / "summary.csv").open() as stream:
        summaries = list(csv.DictReader(stream))
    metrics = {"packet_pps", "tcp_segments_s", "tcp_goodput_mbps", "startup_s",
               "base_load_s", "after_plugin_s", "tx_rtx", "tcp_tx_ratio",
               "packet_errors", "dispatch_errors"}
    expected_keys = {(mode, workers, metric)
                     for mode in ("packet", "template", "vxlan", "geneve")
                     for workers in ("1", "4") for metric in metrics}
    expected_keys.update(("packet", workers, "packet_steady_pps")
                         for workers in ("1", "4"))
    keys = [(row["mode"], row["workers"], row["metric"]) for row in summaries]
    assert len(keys) == len(set(keys)) and set(keys) == expected_keys
    for summary in summaries:
        assert int(summary["n"]) == int(summary["pairs"]) == 6
        values = {}
        for version in ("base", "head"):
            selected = [row for row in rows if row["mode"] == summary["mode"]
                        and row["workers"] == summary["workers"]
                        and row["version"] == version]
            assert {int(row["block"]) for row in selected} == set(range(1, 7))
            values[version] = [float(row[summary["metric"]]) for row in
                               sorted(selected, key=lambda row: int(row["block"]))]
        base, head = values["base"], values["head"]
        check(summary["base_mean"], statistics.mean(base))
        for key, expected in zip(("head_mean", "head_ci_low", "head_ci_high"),
                                 interval(head)):
            check(summary[key], expected)
        differences = [h - b for b, h in zip(base, head)]
        for key, expected in zip(("delta_mean", "delta_ci_low", "delta_ci_high"),
                                 interval(differences)):
            check(summary[key], expected)
        if all(b > 0 for b in base):
            changes = [100 * (h / b - 1) for b, h in zip(base, head)]
            for key, expected in zip(("pct_mean", "pct_ci_low", "pct_ci_high"),
                                     interval(changes)):
                check(summary[key], expected)
    verify_tcp(directory)
    print(f"{directory}: paired summaries verified")


def verify_tcp(directory):
    tcp_rows = json.loads((directory / "tcp-startup-raw.json").read_text())
    assert len(tcp_rows) == 12
    tcp_summary = json.loads((directory / "tcp-startup-summary.json").read_text())
    tcp = {version: {row["block"]: row["startup_s"] for row in tcp_rows
                     if row["version"] == version} for version in ("base", "head")}
    assert all(set(values) == set(range(1, 7)) for values in tcp.values())
    check(tcp_summary["base_mean"], statistics.mean(tcp["base"].values()))
    check(tcp_summary["head_mean"], statistics.mean(tcp["head"].values()))
    mean, low, high = interval([tcp["head"][block] - tcp["base"][block]
                                for block in range(1, 7)])
    check(tcp_summary["delta"], mean)
    check(tcp_summary["ci"][0], low)
    check(tcp_summary["ci"][1], high)


if __name__ == "__main__":
    for argument in sys.argv[1:] or ("initial", "second", "final"):
        verify(Path(__file__).parent / argument)
