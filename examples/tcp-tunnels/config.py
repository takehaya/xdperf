#!/usr/bin/env python3
"""Build mixed.go TCP templates for the Linux tunnel integration test."""
import base64
import ipaddress
import json
import struct
import sys

kind, sm, dm, osrc, odst, isrc, idst, ism, idm, port = sys.argv[1:]

def ip(src, dst, nexthdr):
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if s.version == 4:
        return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 0, 123, 0x4000, 64, nexthdr, 0, s.packed, d.packed)
    return struct.pack('!IHBB16s16s', 0x60000000, 0, nexthdr, 64, s.packed, d.packed)

def eth(src, dst, proto):
    return bytes.fromhex(dst.replace(':', '') + src.replace(':', '')) + struct.pack('!H', proto)

iv = ipaddress.ip_address(isrc).version
ov = ipaddress.ip_address(osrc).version
proto = 0x800 if iv == 4 else 0x86dd
nextip = 4 if iv == 4 else 41
b = eth(sm, dm, 0x800 if ov == 4 else 0x86dd)
lengths, checksums, udps = [], [], []
if kind == 'mpls':
    b = eth(sm, dm, 0x8847) + struct.pack('!I', (200 << 12) | 0x100 | 64)
else:
    nextouter = 47 if kind in ('gre', 'gre-key', 'gretap', 'ip6gre') else nextip
    if kind.startswith('srv6'):
        nextouter = 43
    if kind == 'gtpu':
        nextouter = 17
    b += ip(osrc, odst, nextouter)
    lengths.append(dict(offset=16 if ov == 4 else 18, kind='ipv4' if ov == 4 else 'ipv6', constant=14 if ov == 4 else 54))
    if ov == 4:
        checksums.append(14)
    if nextouter == 47:
        b += struct.pack('!HH', 0x2000 if kind == 'gre-key' else 0, 0x6558 if kind == 'gretap' else proto)
        if kind == 'gre-key':
            b += struct.pack('!I', 7)
        if kind == 'gretap':
            b += eth(ism, idm, proto)
    elif nextouter == 43:
        b += bytes([nextip, 2, 4, 0, 0, 0, 0, 0]) + ipaddress.ip_address(odst).packed
    elif nextouter == 17:
        u = len(b)
        b += struct.pack('!HHHH', 2152, 2152, 0, 0)
        lengths.append(dict(offset=u + 4, kind='udp', constant=u))
        udps.append(dict(offset=u, ip_offset=14, mode='zero'))
        g = len(b)
        b += struct.pack('!BBHI', 0x30, 0xff, 0, 200)
        lengths.append(dict(offset=g + 2, kind='gtpu', constant=g + 8))
l3 = len(b)
b += ip(isrc, idst, 6)
l4 = len(b)
b += struct.pack('!HHIIBBHHH', 0, int(port), 0, 0, 0x50, 0, 0, 0, 0)
for field in lengths:
    field['constant'] = l4 - field['constant']
e = dict(inner_l3_offset=l3, inner_l4_offset=l4, lengths=lengths,
         ipv4_checksums=checksums, udp_checksums=udps)
print(json.dumps(dict(src_ip='192.168.110.1', dst_ip='192.168.110.2', dst_mac=dm,
                     small_bytes='4097', large_bytes='65539',
                     tcp_base=dict(data=base64.b64encode(b).decode(), length=len(b)),
                     tcp_encapsulation=e)))
