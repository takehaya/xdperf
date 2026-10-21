"""Payload verification must be independent of socket receive boundaries."""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import MagicMock

spec = importlib.util.spec_from_file_location(
    'payload_sink', Path(__file__).resolve().parents[2] / 'tcp-payload' / 'sink.py')
sink = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sink)


class PayloadChecks(unittest.TestCase):
    def test_pattern_across_receive_boundaries(self):
        conn = MagicMock()
        conn.recv.side_effect = [b'\x01', b'\x23\xfe\x01\x23', b'\xfe', b'']
        self.assertEqual(sink.receive(conn, bytes.fromhex('0123fe')), 6)
        conn.settimeout.assert_called_once_with(60)

    def test_corrupt_pattern(self):
        conn = MagicMock()
        conn.recv.side_effect = [b'\x01', b'\x01', b'']
        with self.assertRaises(AssertionError):
            sink.receive(conn, bytes.fromhex('0123fe'))

    def test_individual_lengths_not_just_total(self):
        sink.check_totals([65539, 4097, 4097, 4097])
        for totals in ([65539, 4096, 4098, 4097], [77830], [65539, 4097, 4097]):
            with self.subTest(totals=totals), self.assertRaises(AssertionError):
                sink.check_totals(totals)


if __name__ == '__main__':
    unittest.main()
