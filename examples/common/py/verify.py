#!/usr/bin/env python3
"""Check TCP example flow reports against independent receive counters."""
import argparse
import csv
import json
import math


TARGETS = [4097] * 3 + [65539]


def read_summary(path):
    with open(path) as stream:
        return json.loads(stream.readlines()[-1])


def read_stats(path):
    with open(path) as stream:
        line = next(line for line in stream if 'mixed final statistics' in line)
    return json.loads(line[line.index('{'):])


def check_flows(rows, targets=None):
    assert len(rows) == 4 and all(row['state'] == 'done' for row in rows), rows
    if targets is not None:
        assert [int(row['bytes_acked']) for row in rows] == targets, rows
    else:
        assert sum(int(row['bytes_acked']) for row in rows) == 77830, rows


def check_sink(sink, expected_bytes):
    assert sink['accepted'] == sink['closed'] == 4, sink
    assert sink['bytes'] == expected_bytes, sink


def check_rx(stats):
    assert stats['rx_tuple_mismatch'] == stats['rx_invalid_tcp'] == 0, stats


def check_mixed(rows, stats, udp, sink, mode):
    targets = [65536] * 3 + [262144] if mode == 'finite' else [4097] * 3 + [0]
    assert len(rows) == 4, rows
    for i, (row, expected) in enumerate(zip(rows, targets)):
        assert int(row['flow']) == i and row['state'] == 'done', row
        acked = int(row['bytes_acked'])
        assert (acked == expected if expected else acked > 0), row
    check_sink(sink, sum(int(row['bytes_acked']) for row in rows))
    assert stats['packet_tx'] == udp > 0, (stats, udp)
    assert stats['packet_rx'] == udp, stats
    assert stats['tcp_tx'] == sum(int(row['tx_pkts']) for row in rows), stats
    check_rx(stats)
    assert stats['packet_errors'] == stats['dispatch_errors'] == 0, stats
    assert stats['drain_opportunities'] > 0, stats
    opportunities = stats['tcp_opportunities'] + stats['packet_opportunities']
    assert abs(stats['tcp_opportunities'] / opportunities - .25) < .03, stats
    assert math.isclose(stats['tcp_tx_ratio'], stats['tcp_tx'] / (stats['tcp_tx'] + udp),
                        abs_tol=1e-6), stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='scenario', required=True)
    for name in ('template', 'tunnel', 'payload', 'mixed'):
        command = commands.add_parser(name)
        command.add_argument('report')
        if name != 'payload':
            command.add_argument('sink_log')
        if name != 'template':
            command.add_argument('tx_log')
        if name == 'mixed':
            command.add_argument('udp_log')
            command.add_argument('mode', choices=('finite', 'duration'))
    args = parser.parse_args()
    with open(args.report, newline='') as stream:
        rows = list(csv.DictReader(stream))
    if args.scenario == 'mixed':
        stats = read_stats(args.tx_log)
        check_mixed(rows, stats, read_summary(args.udp_log)['udp_packets'],
                    read_summary(args.sink_log), args.mode)
        print('PASS:', stats)
    else:
        check_flows(rows, None if args.scenario == 'payload' else TARGETS)
        if args.scenario != 'payload':
            check_sink(read_summary(args.sink_log), 77830)
        if args.scenario != 'template':
            check_rx(read_stats(args.tx_log))


if __name__ == '__main__':
    main()
