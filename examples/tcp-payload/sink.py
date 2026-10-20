#!/usr/bin/env python3
"""Check the pattern at every stream position, independent of recv boundaries."""
import concurrent.futures
import json
import socket
import sys

address, version, text = sys.argv[1:]
pattern = bytes.fromhex(text)
listener = socket.socket(socket.AF_INET6 if version == "6" else socket.AF_INET)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.settimeout(60)
listener.bind((address, 5201))
listener.listen(4)
print("ready", flush=True)


def receive(conn):
    offset = 0
    with conn:
        conn.settimeout(60)
        while True:
            data = conn.recv(65536)
            if not data:
                return offset
            expected = (pattern * ((len(data) + len(pattern) - 1) // len(pattern) + 1))
            start = offset % len(pattern)
            assert data == expected[start:start + len(data)], (offset, len(data))
            offset += len(data)


with listener, concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    tasks = [pool.submit(receive, listener.accept()[0]) for _ in range(4)]
    totals = sorted(task.result() for task in tasks)
assert totals == [4097, 4097, 4097, 65539], totals
print(json.dumps({"flows": 4, "bytes": sum(totals)}), flush=True)
