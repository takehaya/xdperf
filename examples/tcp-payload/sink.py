#!/usr/bin/env python3
"""Check the pattern at every stream position, independent of recv boundaries."""
import argparse
import concurrent.futures
import json
import socket


def receive(conn, pattern):
    offset = 0
    with conn:
        conn.settimeout(60)
        while True:
            data = conn.recv(65536)
            if not data:
                return offset
            expected = pattern * ((len(data) + len(pattern) - 1) // len(pattern) + 1)
            start = offset % len(pattern)
            assert data == expected[start:start + len(data)], (offset, len(data))
            offset += len(data)


def check_totals(totals):
    assert sorted(totals) == [4097, 4097, 4097, 65539], totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('address')
    parser.add_argument('version', choices=('4', '6'))
    parser.add_argument('pattern', help='nonempty repeating pattern in hex')
    args = parser.parse_args()
    try:
        pattern = bytes.fromhex(args.pattern)
    except ValueError:
        parser.error('pattern must contain hex bytes')
    if not pattern:
        parser.error('pattern must not be empty')
    family = socket.AF_INET6 if args.version == '6' else socket.AF_INET
    with socket.socket(family) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(60)
        listener.bind((args.address, 5201))
        listener.listen(4)
        print('ready', flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            tasks = [pool.submit(receive, listener.accept()[0], pattern) for _ in range(4)]
            totals = [task.result() for task in tasks]
    check_totals(totals)
    print(json.dumps({'flows': 4, 'bytes': sum(totals)}), flush=True)


if __name__ == '__main__':
    main()
