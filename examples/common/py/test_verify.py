"""Regression tests for example checks, including rejection of bad results."""
import copy
import tempfile
import unittest
from pathlib import Path

from udp_echo import check_packet
from verify import (TARGETS, check_flows, check_mixed, check_rx, check_sink,
                    read_stats, read_summary)


class ReportChecks(unittest.TestCase):
    def setUp(self):
        self.rows = [dict(flow=str(i), state='done', bytes_acked=str(n), tx_pkts='10')
                     for i, n in enumerate([65536] * 3 + [262144])]
        self.sink = dict(accepted=4, closed=4, bytes=458752)
        self.stats = dict(packet_tx=120, packet_rx=120, tcp_tx=40,
                          rx_tuple_mismatch=0, rx_invalid_tcp=0, packet_errors=0,
                          dispatch_errors=0, drain_opportunities=1,
                          tcp_opportunities=100, packet_opportunities=300,
                          tcp_tx_ratio=.25)

    def check_mixed(self, mode='finite'):
        check_mixed(self.rows, self.stats, 120, self.sink, mode)

    def test_mixed_finite_and_duration(self):
        self.check_mixed()
        for row, n in zip(self.rows, [4097] * 3 + [123456]):
            row['bytes_acked'] = str(n)
        self.sink['bytes'] = 4097 * 3 + 123456
        self.check_mixed('duration')
        self.rows[-1]['bytes_acked'] = '0'
        with self.assertRaises(AssertionError):
            self.check_mixed('duration')

    def test_each_mixed_counter_is_enforced(self):
        invalid = dict(packet_tx=119, packet_rx=119, tcp_tx=41,
                       rx_tuple_mismatch=1, rx_invalid_tcp=1, packet_errors=1,
                       dispatch_errors=1, drain_opportunities=0,
                       tcp_opportunities=150, packet_opportunities=400,
                       tcp_tx_ratio=.251)
        for key, value in invalid.items():
            with self.subTest(key=key):
                stats = dict(self.stats, **{key: value})
                with self.assertRaises(AssertionError):
                    check_mixed(self.rows, stats, 120, self.sink, 'finite')
        zero_udp = dict(self.stats, packet_tx=0, packet_rx=0, tcp_tx_ratio=1.0)
        with self.assertRaises(AssertionError):
            check_mixed(self.rows, zero_udp, 0, self.sink, 'finite')

    def test_mixed_rows_and_sink_are_enforced(self):
        for field, value in [('flow', '1'), ('state', 'failed'), ('bytes_acked', '65535')]:
            with self.subTest(field=field):
                rows = copy.deepcopy(self.rows)
                rows[0][field] = value
                with self.assertRaises(AssertionError):
                    check_mixed(rows, self.stats, 120, self.sink, 'finite')
        with self.assertRaises(AssertionError):
            check_mixed(self.rows[:-1], self.stats, 120, self.sink, 'finite')
        for key in self.sink:
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_sink(dict(self.sink, **{key: 0}), 458752)

    def test_opportunity_and_ratio_tolerances(self):
        self.stats.update(tcp_opportunities=279, packet_opportunities=721)
        self.stats['tcp_tx_ratio'] += .0000009
        self.check_mixed()
        self.stats.update(tcp_opportunities=281, packet_opportunities=719)
        with self.assertRaises(AssertionError):
            self.check_mixed()

    def test_template_targets_and_payload_total(self):
        rows = [dict(state='done', bytes_acked=str(n)) for n in TARGETS]
        check_flows(rows, TARGETS)
        check_flows(rows)
        check_sink(dict(accepted=4, closed=4, bytes=77830), 77830)
        rows[0]['bytes_acked'] = '4096'
        rows[1]['bytes_acked'] = '4098'
        check_flows(rows)  # Payload CSV checks totals; its sink checks each stream.
        with self.assertRaises(AssertionError):
            check_flows(rows, TARGETS)
        rows[0]['state'] = 'failed'
        with self.assertRaises(AssertionError):
            check_flows(rows)
        rows[0]['state'] = 'done'
        rows[0]['bytes_acked'] = '0'
        with self.assertRaises(AssertionError):
            check_flows(rows)
        with self.assertRaises(AssertionError):
            check_flows(rows[:-1])

    def test_receive_errors(self):
        check_rx(self.stats)
        for key in ('rx_tuple_mismatch', 'rx_invalid_tcp'):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_rx(dict(self.stats, **{key: 1}))

    def test_log_readers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.log'
            path.write_text('ready\n{"udp_packets": 123}\n')
            self.assertEqual(read_summary(path), {'udp_packets': 123})
            path.write_text('startup\ntimestamp INFO mixed final statistics\t{"packet_tx": 123}\ncleanup\n')
            self.assertEqual(read_stats(path), {'packet_tx': 123})
            path.write_text('startup\n')
            with self.assertRaises(StopIteration):
                read_stats(path)
            with self.assertRaises(ValueError):
                read_summary(path)

    def test_udp_dns_contents(self):
        packet = bytes.fromhex('12340100') + bytes(8) + b'\x07example'
        check_packet(packet)
        for bad in (b'', bytes(4) + packet[4:], packet[:12] + b'\x07invalid'):
            with self.subTest(packet=bad), self.assertRaises(AssertionError):
                check_packet(bad)


if __name__ == '__main__':
    unittest.main()
