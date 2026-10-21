#!/usr/bin/env python3
"""Build mixed.go configurations for the TCP example scenarios."""
import argparse
import base64
import ipaddress
import json
import struct


def ethernet(src, dst, protocol):
    return bytes.fromhex(dst.replace(':', '') + src.replace(':', '')) + struct.pack('!H', protocol)


def ip_header(src, dst, next_header, *, template=False, payload=False):
    src, dst = (ipaddress.ip_address(src), ipaddress.ip_address(dst))
    ttl = 37 if template else 64
    if src.version == 4:
        return struct.pack('!BBHHHBBH4s4s', 0x45, 0xa8 if template else 0, 40 if payload else 0,
            0x1234 if template else 0 if payload else 123, 0x4000, ttl, next_header, 0, src.packed,
            dst.packed)
    return struct.pack('!IHBB16s16s', 0x6ac12345 if template else 0x60000000, 20 if payload else 0,
        next_header, ttl, src.packed, dst.packed)


def tcp_header(port):
    return struct.pack('!HHIIBBHHH', 0, int(port), 0, 0, 0x50, 0, 0, 0, 0)


def flow_config(dst_mac, src_ip, dst_ip, frame, **features):
    return dict(src_ip=src_ip, dst_ip=dst_ip, dst_mac=dst_mac, small_bytes='4097',
        large_bytes='65539',
        tcp_base=dict(data=base64.b64encode(frame).decode(), length=len(frame)), **features)


def mixed(args):
    return dict(src_ip=args.src_ip, dst_ip=args.dst_ip, dst_mac=args.dst_mac,
        small_bytes=args.small_bytes, large_bytes=args.large_bytes, tcp_port=int(args.tcp_port))


def template(args):
    version = ipaddress.ip_address(args.src).version
    frame = bytes.fromhex(args.dm.replace(':', '') + args.sm.replace(':', ''))
    if int(args.tags) == 1:
        frame += struct.pack('!HH', 0x8100, 110)
    if int(args.tags) == 2:
        frame += struct.pack('!HHHH', 0x88a8, 120, 0x8100, 121)
    frame += struct.pack('!H', 0x800 if version == 4 else 0x86dd)
    frame += ip_header(args.src, args.dst, 6, template=True, payload=True)
    frame += tcp_header(args.port)
    return flow_config(args.dm, args.udp_src, args.udp_dst, frame, syn_options='BAIBAQ==',
        data_options='AQEBAQ==')


def vxlan(args):
    sm, dm, osrc, odst, ism, idm, isrc, idst, mode, port, usrc, udst = (args.sm, args.dm, args.osrc,
        args.odst, args.ism, args.idm, args.isrc, args.idst, args.mode, args.port, args.usrc,
        args.udst)
    ov = ipaddress.ip_address(osrc).version
    iv = ipaddress.ip_address(isrc).version
    b = ethernet(sm, dm, 0x800 if ov == 4 else 0x86dd) + ip_header(osrc, odst, 17, template=True)
    u = len(b)
    b += struct.pack('!HHHH', 49152, 4789, 0, 0) + bytes.fromhex('0800000000000700') + ethernet(ism,
        idm, 0x800 if iv == 4 else 0x86dd)
    l3 = len(b)
    b += ip_header(isrc, idst, 6, template=True)
    l4 = len(b)
    b += tcp_header(port)
    e = dict(inner_l3_offset=l3, inner_l4_offset=l4,
        lengths=[dict(offset=16 if ov == 4 else 18, kind='ipv4' if ov == 4 else 'ipv6',
                      constant=l4 - (14 if ov == 4 else 54)),
                 dict(offset=u + 4, kind='udp', constant=l4 - u)],
        ipv4_checksums=[14] if ov == 4 else [],
        udp_checksums=[dict(offset=u, ip_offset=14, mode=mode)],
        udp_source_port=dict(offset=u, base=49152, count=16384))
    return flow_config(dm, usrc, udst, b, tcp_encapsulation=e, syn_options='BAIBAQ==',
        data_options='AQEBAQ==')


def payload(args):
    sm, dm, src, dst, feature, pattern, us, ud = (args.sm, args.dm, args.src, args.dst,
        args.feature, args.pattern, args.us, args.ud)
    src, dst = (ipaddress.ip_address(src), ipaddress.ip_address(dst))
    b = ethernet(sm, dm, 0x800 if src.version == 4 else 0x86dd)
    b += ip_header(str(src), str(dst), 6, payload=True) + tcp_header(5201)
    c = flow_config(dm, us, ud, b,
        timestamps=feature in ('timestamps', 'declined', 'combined', 'loss'),
        payload_pattern=base64.b64encode(bytes.fromhex(pattern)).decode())
    if feature in ('variables', 'combined', 'loss'):
        # IPv6 textual ::11 is hex 0x11.
        first = 11 if src.version == 4 else 17
        c['flow_variable_params'] = [dict(
            byte_start=29 if src.version == 4 else 37, byte_size=1,
            byte_range=dict(start=first, end=first + 3), pattern_type='sequential')]
    return c


def tunnel(args):
    kind, sm, dm, osrc, odst, isrc, idst, ism, idm, port = (args.kind, args.sm, args.dm, args.osrc,
        args.odst, args.isrc, args.idst, args.ism, args.idm, args.port)
    iv = ipaddress.ip_address(isrc).version
    ov = ipaddress.ip_address(osrc).version
    proto = 0x800 if iv == 4 else 0x86dd
    nextip = 4 if iv == 4 else 41
    b = ethernet(sm, dm, 0x800 if ov == 4 else 0x86dd)
    lengths, checksums, udps = ([], [], [])
    if kind == 'mpls':
        b = ethernet(sm, dm, 0x8847) + struct.pack('!I', (200 << 12) | 0x100 | 64)
    else:
        nextouter = 47 if kind in ('gre', 'gre-key', 'gretap', 'ip6gre') else nextip
        if kind.startswith('srv6'):
            nextouter = 43
        if kind == 'gtpu':
            nextouter = 17
        b += ip_header(osrc, odst, nextouter)
        lengths.append(dict(offset=16 if ov == 4 else 18,
                            kind='ipv4' if ov == 4 else 'ipv6',
                            constant=14 if ov == 4 else 54))
        if ov == 4:
            checksums.append(14)
        if nextouter == 47:
            b += struct.pack('!HH', 0x2000 if kind == 'gre-key' else 0,
                0x6558 if kind == 'gretap' else proto)
            if kind == 'gre-key':
                b += struct.pack('!I', 7)
            if kind == 'gretap':
                b += ethernet(ism, idm, proto)
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
    b += ip_header(isrc, idst, 6)
    l4 = len(b)
    b += tcp_header(port)
    for field in lengths:
        field['constant'] = l4 - field['constant']
    e = dict(inner_l3_offset=l3, inner_l4_offset=l4, lengths=lengths, ipv4_checksums=checksums,
        udp_checksums=udps)
    return flow_config(dm, '192.168.110.1', '192.168.110.2', b, tcp_encapsulation=e)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='scenario', required=True)
    command = commands.add_parser('mixed')
    command.add_argument('src_ip')
    command.add_argument('dst_ip')
    command.add_argument('dst_mac')
    command.add_argument('small_bytes')
    command.add_argument('large_bytes')
    command.add_argument('tcp_port')
    command.set_defaults(build=mixed)
    command = commands.add_parser('template')
    command.add_argument('sm')
    command.add_argument('dm')
    command.add_argument('src')
    command.add_argument('dst')
    command.add_argument('tags')
    command.add_argument('port')
    command.add_argument('udp_src')
    command.add_argument('udp_dst')
    command.set_defaults(build=template)
    command = commands.add_parser('vxlan')
    command.add_argument('sm')
    command.add_argument('dm')
    command.add_argument('osrc')
    command.add_argument('odst')
    command.add_argument('ism')
    command.add_argument('idm')
    command.add_argument('isrc')
    command.add_argument('idst')
    command.add_argument('mode')
    command.add_argument('port')
    command.add_argument('usrc')
    command.add_argument('udst')
    command.set_defaults(build=vxlan)
    command = commands.add_parser('payload')
    command.add_argument('sm')
    command.add_argument('dm')
    command.add_argument('src')
    command.add_argument('dst')
    command.add_argument('feature')
    command.add_argument('pattern')
    command.add_argument('us')
    command.add_argument('ud')
    command.set_defaults(build=payload)
    command = commands.add_parser('tunnel')
    command.add_argument('kind')
    command.add_argument('sm')
    command.add_argument('dm')
    command.add_argument('osrc')
    command.add_argument('odst')
    command.add_argument('isrc')
    command.add_argument('idst')
    command.add_argument('ism')
    command.add_argument('idm')
    command.add_argument('port')
    command.set_defaults(build=tunnel)
    args = parser.parse_args()
    print(json.dumps(args.build(args)))
if __name__ == '__main__':
    main()
