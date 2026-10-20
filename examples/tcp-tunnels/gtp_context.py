#!/usr/bin/env python3
"""Install one GTPv1 PDP context via the kernel's generic netlink API.

The link is created with `ip link add ... type gtp role ggsn`; its kernel-owned
UDP sockets need no userspace daemon. Run this helper in the receiver netns.
"""
import ipaddress
import os
import socket
import struct
import sys


def attr(kind, data):
    size = 4 + len(data)
    return struct.pack('HH', size, kind) + data + bytes((-size) % 4)


def u32(kind, value):
    return attr(kind, struct.pack('I', value))


def attrs(data):
    while len(data) >= 4:
        size, kind = struct.unpack_from('HH', data)
        if size < 4 or size > len(data):
            raise ValueError('invalid netlink attribute')
        yield kind, data[4:size]
        data = data[(size + 3) & ~3:]


def request(sock, family, command, payload, seq):
    body = struct.pack('BBH', command, 1, 0) + payload
    # NLM_F_REQUEST | NLM_F_ACK; NEWPDP uses NLM_F_EXCL | NLM_F_CREATE.
    flags = 5 | (0x600 if command == 0 else 0)
    sock.send(struct.pack('IHHII', 16 + len(body), family, flags, seq, 0) + body)
    result = None
    while True:
        data = sock.recv(65536)
        while len(data) >= 16:
            size, kind, _, reply_seq, _ = struct.unpack_from('IHHII', data)
            if size < 16 or size > len(data) or reply_seq != seq:
                raise ValueError('invalid netlink response')
            body = data[16:size]
            if kind == 2:
                error = struct.unpack_from('i', body)[0]
                if error:
                    raise OSError(-error, os.strerror(-error))
                return result
            result = body
            data = data[(size + 3) & ~3:]


def main():
    dev, peer, ms = sys.argv[1:]
    peer, ms = ipaddress.ip_address(peer), ipaddress.ip_address(ms)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16) as sock:
        sock.bind((0, 0))
        sock.settimeout(5)
        response = request(sock, 16, 3, attr(2, b'gtp\0'), 1)
        family_attrs = dict(attrs(response[4:]))
        family = struct.unpack('H', family_attrs[1])[0]
        maxattr = struct.unpack('I', family_attrs[5])[0]
        if ms.version == 6 and maxattr < 13:
            print('SKIP gtpu IPv6: kernel PDP API has no address-family attribute; use TestTCPReceiveTunnels')
            sys.exit(3)
        payload = u32(1, socket.if_nametoindex(dev)) + u32(2, 1)
        # The kernel stores IPv6 mobile subscribers by /64 prefix.
        ms_bytes = ms.packed if ms.version == 4 else ms.packed[:8] + bytes(8)
        payload += attr(4, peer.packed) + attr(5 if ms.version == 4 else 12, ms_bytes)
        payload += u32(8, 200) + u32(9, 100)
        if ms.version == 6:
            payload += attr(13, bytes([socket.AF_INET6]))
        request(sock, family, 0, payload, 2)


if __name__ == '__main__':
    main()
