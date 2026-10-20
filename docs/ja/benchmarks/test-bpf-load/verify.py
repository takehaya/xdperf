#!/usr/bin/env python3
"""Recompute paired package times and check the preserved Go test inventory.

Usage: python3 verify.py RAW.csv BEFORE-list.txt AFTER-list.txt [SUMMARY.csv]
Raw inputs stay outside git; the optional summary argument checks committed data.
"""

import csv
import math
from pathlib import Path
import statistics
import sys

# Two-sided Student t, 95%, df=2. The protocol fixes three pairs per package.
T95_DF2 = 4.302652729911275
FIELDS = ["package", "pairs", "before_s", "after_s", "difference_s", "ci95_low_s", "ci95_high_s", "tests_before", "tests_after"]


def inventory(path):
    result, names = {}, []
    for line in Path(path).read_text().splitlines():
        if line.startswith(("Test", "Benchmark", "Example")):
            names.append(line)
        elif line.startswith("ok"):
            package = line.split()[1]
            assert package not in result, f"duplicate package: {package}"
            result[package] = set(names)
            assert len(result[package]) == len(names), f"duplicate test: {package}"
            names = []
    assert not names and result, "incomplete test inventory"
    return result


def summarize(raw, before, after):
    assert before.keys() == after.keys(), "package inventory changed"
    groups = {}
    for row in csv.DictReader(Path(raw).open()):
        package, block, version = row["package"], int(row["block"]), row["version"]
        assert package in before and version in ("before", "after")
        assert row["status"] == "0", f"failed trial: {row}"
        seconds = float(row["seconds"])
        assert math.isfinite(seconds) and seconds > 0
        pair = groups.setdefault(package, {}).setdefault(block, {})
        assert version not in pair, f"duplicate trial: {row}"
        pair[version] = seconds
    assert groups.keys() == before.keys(), "missing package measurements"
    rows = []
    for package in sorted(groups):
        assert before[package] <= after[package], f"removed tests: {package}"
        blocks = groups[package]
        assert set(blocks) == {1, 2, 3}, f"expected three pairs: {package}"
        assert all(set(pair) == {"before", "after"} for pair in blocks.values())
        pairs = [blocks[i] for i in (1, 2, 3)]
        differences = [pair["after"] - pair["before"] for pair in pairs]
        mean = statistics.mean(differences)
        margin = T95_DF2 * statistics.stdev(differences) / math.sqrt(3)
        rows.append(dict(zip(FIELDS, [
            package, 3,
            statistics.mean(pair["before"] for pair in pairs),
            statistics.mean(pair["after"] for pair in pairs),
            mean, mean - margin, mean + margin,
            len(before[package]), len(after[package]),
        ])))
    return rows


def main():
    raw, before_path, after_path = sys.argv[1:4]
    rows = summarize(raw, inventory(before_path), inventory(after_path))
    if len(sys.argv) == 5:
        with Path(sys.argv[4]).open() as source:
            saved = list(csv.DictReader(source))
        assert len(saved) == len(rows)
        for expected, actual in zip(saved, rows):
            assert expected["package"] == actual["package"]
            for field in FIELDS[1:]:
                assert math.isclose(float(expected[field]), actual[field], abs_tol=1e-6), field
        print("Paired times, Student t CIs and test inventory verified.", file=sys.stderr)
    writer = csv.DictWriter(sys.stdout, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: f"{value:.6f}" if isinstance(value, float) else value for key, value in row.items()})


if __name__ == "__main__":
    main()
