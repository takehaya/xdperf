#!/usr/bin/env python3
"""Echo DNS-style UDP packets and count them independently of xdperf."""
import argparse
import json
import signal
import socket


def check_packet(data):
    assert data[:4] == bytes.fromhex('12340100') and data[12:20] == b'\x07example', data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('address')
    args = parser.parse_args()
    running, count = True, 0

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.address, 5353))
        sock.settimeout(.1)
        print('ready', flush=True)
        while running:
            try:
                data, peer = sock.recvfrom(65535)
                check_packet(data)
                count += 1
                sock.sendto(data, peer)
            except socket.timeout:
                pass
    print(json.dumps({'udp_packets': count}))


if __name__ == '__main__':
    main()
