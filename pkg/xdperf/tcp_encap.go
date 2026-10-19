package xdperf

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
)

const tcpTemplateLimit = 256

type tcpOuterIP struct {
	offset  int
	version uint8
}
type tcpOuterUDP struct {
	offset, ipOffset int
	version          uint8
}
type parsedTCPEncap struct {
	target  *tcpTarget
	lengths []guest.TCPLengthField
	ips     []tcpOuterIP
	udps    []tcpOuterUDP
}

func parseTCPVariant(v guest.PacketVariant) (*tcpTarget, error) {
	if v.TCPFlow == nil || v.TCPFlow.Encapsulation == nil {
		return parseTCPBase(v.Base)
	}
	p, err := parseTCPEncapsulation(v.Base, v.TCPFlow.Encapsulation)
	if err != nil {
		return nil, err
	}
	return p.target, nil
}

// Parse known tunnel formats, then compare the explicit fixup table. Input IP
// length/checksum fields remain placeholders, just as for a bare template.
func parseTCPEncapsulation(base guest.BasePacket, e *guest.TCPEncapsulation) (*parsedTCPEncap, error) {
	b := base.Data
	if len(b) != int(base.Length) || len(b) > tcpTemplateLimit || len(b) < 54 {
		return nil, fmt.Errorf("encapsulated TCP base length must match data and be 54..256")
	}
	p := &parsedTCPEncap{}
	usedEncap := false
	need := func(off, n int) bool { return off >= 0 && n >= 0 && off+n <= len(b) }
	eth := func(off int) (int, uint16, error) {
		if !need(off, 14) {
			return 0, 0, fmt.Errorf("truncated inner Ethernet")
		}
		proto := binary.BigEndian.Uint16(b[off+12:])
		off += 14
		for i := 0; i < 2 && (proto == 0x8100 || proto == 0x88a8); i++ {
			if !need(off, 4) {
				return 0, 0, fmt.Errorf("truncated VLAN")
			}
			proto = binary.BigEndian.Uint16(b[off+2:])
			off += 4
		}
		return off, proto, nil
	}
	off, proto, err := eth(0)
	if err != nil {
		return nil, err
	}
	rawIP := func(off int) (uint16, error) {
		if !need(off, 1) {
			return 0, fmt.Errorf("missing inner IP")
		}
		switch b[off] >> 4 {
		case 4:
			return 0x0800, nil
		case 6:
			return 0x86dd, nil
		}
		return 0, fmt.Errorf("unknown inner IP version")
	}
	for depth := 0; depth <= 4; depth++ {
		if proto == 0x8847 || proto == 0x8848 {
			usedEncap = true
			bottom := false
			for i := 0; i < 8; i++ {
				if !need(off, 4) {
					return nil, fmt.Errorf("truncated MPLS")
				}
				bottom = b[off+2]&1 != 0
				off += 4
				if bottom {
					break
				}
			}
			if !bottom {
				return nil, fmt.Errorf("MPLS stack exceeds 8 labels")
			}
			proto, err = rawIP(off)
			if err != nil {
				return nil, err
			}
		}
		ipoff := off
		var version, next uint8
		switch proto {
		case 0x0800:
			if !need(off, 20) || b[off] != 0x45 || binary.BigEndian.Uint16(b[off+6:])&0x3fff != 0 {
				return nil, fmt.Errorf("unsupported outer IPv4 options/version/fragment")
			}
			version, next = 4, b[off+9]
			off += 20
		case 0x86dd:
			if !need(off, 40) || b[off]>>4 != 6 {
				return nil, fmt.Errorf("invalid outer IPv6")
			}
			version, next = 6, b[off+6]
			off += 40
		default:
			return nil, fmt.Errorf("unsupported encapsulation EtherType %#x", proto)
		}
		if next == 6 {
			// Reuse the bare TCP structural checks with a synthetic Ethernet header.
			inner := append([]byte(nil), b[:14]...)
			binary.BigEndian.PutUint16(inner[12:], proto)
			inner = append(inner, b[ipoff:]...)
			t, err := parseTCPBase(guest.BasePacket{Data: inner, Length: uint16(len(inner))})
			if err != nil {
				return nil, err
			}
			t.l3Off, t.l4Off, t.hdrLen = uint16(ipoff), uint16(off), uint16(off+20)
			p.target = t
			break
		}
		if depth == 4 {
			return nil, fmt.Errorf("TCP encapsulation exceeds four outer IP layers")
		}
		usedEncap = true
		p.ips = append(p.ips, tcpOuterIP{ipoff, version})
		kind, field, start := "ipv4", ipoff+2, ipoff
		if version == 6 {
			kind, field, start = "ipv6", ipoff+4, ipoff+40
		}
		// Constant stores the subtraction origin until the final TCP offset is known.
		p.lengths = append(p.lengths, guest.TCPLengthField{Offset: uint16(field), Kind: kind, Constant: uint16(start)})
		if next == 43 && version == 6 {
			if !need(off, 8) || b[off+2] != 4 {
				return nil, fmt.Errorf("only SRH routing headers are supported")
			}
			n := (int(b[off+1]) + 1) * 8
			if !need(off, n) || n < 8+16*(int(b[off+4])+1) || b[off+3] > b[off+4]+1 {
				return nil, fmt.Errorf("invalid SRH length/segments")
			}
			next = b[off]
			off += n
			if next != 4 && next != 41 && next != 143 {
				return nil, fmt.Errorf("SRH requires an inner IP or Ethernet packet")
			}
		}
		switch next {
		case 4:
			proto = 0x0800
		case 41:
			proto = 0x86dd
		case 143:
			off, proto, err = eth(off)
			if err != nil {
				return nil, err
			}
		case 17:
			if !need(off, 8) {
				return nil, fmt.Errorf("truncated outer UDP")
			}
			udp := off
			port := binary.BigEndian.Uint16(b[off+2:])
			off += 8
			p.udps = append(p.udps, tcpOuterUDP{udp, ipoff, version})
			p.lengths = append(p.lengths, guest.TCPLengthField{Offset: uint16(udp + 4), Kind: "udp", Constant: uint16(udp)})
			switch port {
			case 4789:
				if !need(off, 8) || b[off] != 8 || b[off+1] != 0 || b[off+2] != 0 || b[off+3] != 0 || b[off+7] != 0 {
					return nil, fmt.Errorf("invalid VXLAN header")
				}
				off += 8
				off, proto, err = eth(off)
			case 6081:
				if !need(off, 8) || b[off]>>6 != 0 || b[off+1] != 0 || b[off+7] != 0 {
					return nil, fmt.Errorf("unsupported GENEVE version/flags")
				}
				n := 8 + int(b[off]&63)*4
				if !need(off, n) {
					return nil, fmt.Errorf("truncated GENEVE options")
				}
				// Critical options require protocol-specific processing, which is absent.
				for o := off + 8; o < off+n; {
					if !need(o, 4) || b[o+2]&0x80 != 0 || b[o+3]&0xe0 != 0 {
						return nil, fmt.Errorf("unsupported GENEVE option")
					}
					l := 4 + int(b[o+3]&31)*4
					if o+l > off+n {
						return nil, fmt.Errorf("invalid GENEVE option length")
					}
					o += l
				}
				proto = binary.BigEndian.Uint16(b[off+2:])
				off += n
				if proto == 0x6558 {
					off, proto, err = eth(off)
				}
			case 2152:
				if !need(off, 8) || b[off]&0xf8 != 0x30 || b[off+1] != 0xff {
					return nil, fmt.Errorf("expected GTPv1-U G-PDU")
				}
				gtp := off
				flags := b[off]
				if flags&3 != 0 {
					return nil, fmt.Errorf("GTP-U sequence/N-PDU numbering unsupported without per-packet sequencing")
				}
				off += 8
				p.lengths = append(p.lengths, guest.TCPLengthField{Offset: uint16(gtp + 2), Kind: "gtpu", Constant: uint16(gtp + 8)})
				if flags&7 != 0 {
					if !need(off, 4) {
						return nil, fmt.Errorf("truncated GTP optional fields")
					}
					ext := b[off+3]
					off += 4
					if flags&4 == 0 && ext != 0 {
						return nil, fmt.Errorf("GTP next extension without E flag")
					}
					for i := 0; ext != 0 && i < 8; i++ {
						if !need(off, 1) {
							return nil, fmt.Errorf("truncated GTP extension")
						}
						n := int(b[off]) * 4
						if n < 4 || !need(off, n) {
							return nil, fmt.Errorf("invalid GTP extension length")
						}
						ext = b[off+n-1]
						off += n
					}
					if ext != 0 {
						return nil, fmt.Errorf("GTP extension chain exceeds 8")
					}
				}
				proto, err = rawIP(off)
			default:
				return nil, fmt.Errorf("unsupported outer UDP port %d", port)
			}
			if err != nil {
				return nil, err
			}
		case 47:
			if !need(off, 4) {
				return nil, fmt.Errorf("truncated GRE")
			}
			flags := binary.BigEndian.Uint16(b[off:])
			proto = binary.BigEndian.Uint16(b[off+2:])
			off += 4
			// Checksums and sequence numbers require per-packet engine updates.
			if flags&^uint16(0x2000) != 0 {
				return nil, fmt.Errorf("GRE supports only version 0 with optional key; checksum/routing/sequence unsupported")
			}
			if flags&0x2000 != 0 {
				off += 4
			}
			if !need(off, 0) {
				return nil, fmt.Errorf("truncated GRE fields")
			}
			if proto == 0x6558 {
				off, proto, err = eth(off)
				if err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("unsupported encapsulation IP protocol %d", next)
		}
	}
	if p.target == nil {
		return nil, fmt.Errorf("encapsulation does not end in TCP")
	}
	if int(e.InnerL3Offset) != int(p.target.l3Off) || int(e.InnerL4Offset) != int(p.target.l4Off) {
		return nil, fmt.Errorf("inner offsets disagree with parsed TCP")
	}
	if !usedEncap {
		return nil, fmt.Errorf("encapsulation metadata requires a tunnel or MPLS")
	}
	if len(p.lengths) > 8 || len(p.ips) > 4 || len(p.udps) > 4 {
		return nil, fmt.Errorf("encapsulation exceeds patch limits")
	}
	for i := range p.lengths {
		p.lengths[i].Constant = p.target.l4Off - p.lengths[i].Constant
	}
	if len(p.lengths) != len(e.Lengths) || (len(p.lengths) > 0 && !reflect.DeepEqual(p.lengths, e.Lengths)) {
		return nil, fmt.Errorf("length patches disagree with parsed headers (expected %+v)", p.lengths)
	}
	var v4 []uint16
	for _, ip := range p.ips {
		if ip.version == 4 {
			v4 = append(v4, uint16(ip.offset))
		}
	}
	if len(v4) != len(e.IPv4Checksums) {
		return nil, fmt.Errorf("IPv4 checksum list is incomplete")
	}
	for i := range v4 {
		if v4[i] != e.IPv4Checksums[i] {
			return nil, fmt.Errorf("IPv4 checksum offsets disagree")
		}
	}
	if len(e.UDPChecksums) != len(p.udps) {
		return nil, fmt.Errorf("UDP checksum list is incomplete")
	}
	for i, u := range p.udps {
		spec := e.UDPChecksums[i]
		if int(spec.Offset) != u.offset || int(spec.IPOffset) != u.ipOffset || (spec.Mode != "lco" && spec.Mode != "zero") || (u.version == 6 && spec.Mode == "zero") {
			return nil, fmt.Errorf("invalid outer UDP checksum specification")
		}
	}
	if port := e.UDPSourcePort; port != nil {
		found := false
		for _, u := range p.udps {
			found = found || int(port.Offset) == u.offset
		}
		if !found || port.Base == 0 || port.Count == 0 || uint32(port.Base)+uint32(port.Count) > 65536 {
			return nil, fmt.Errorf("invalid UDP source port entropy range/offset")
		}
	}
	return p, nil
}

func initTCPEncapsulation(t *coreelf.BpfTcpTemplate, v guest.PacketVariant) error {
	e := v.TCPFlow.Encapsulation
	p, err := parseTCPEncapsulation(v.Base, e)
	if err != nil {
		return err
	}
	t.LengthCount = uint8(len(p.lengths))
	t.OuterIpCount = uint8(len(p.ips))
	t.UdpCount = uint8(len(p.udps))
	for i, l := range p.lengths {
		t.Lengths[i].Offset = l.Offset
		t.Lengths[i].Constant = l.Constant
	}
	for i, ip := range p.ips {
		t.OuterIps[i].Offset = uint16(ip.offset)
		t.OuterIps[i].Version = ip.version
		if ip.version == 4 {
			t.Prefix[ip.offset+1] &^= 3
		} else {
			t.Prefix[ip.offset+1] &^= 0x30
		}
	}
	for i, u := range p.udps {
		d := &t.Udps[i]
		d.Offset = uint16(u.offset)
		d.IpOffset = uint16(u.ipOffset)
		d.Version = u.version
		if e.UDPChecksums[i].Mode == "lco" {
			d.Mode = 1
		}
		b := v.Base.Data
		if u.version == 4 {
			d.PseudoSum = pseudoHeaderAddrSum(b[u.ipOffset+12:u.ipOffset+16], b[u.ipOffset+16:u.ipOffset+20])
		} else {
			d.PseudoSum = pseudoHeaderAddrSum(b[u.ipOffset+8:u.ipOffset+24], b[u.ipOffset+24:u.ipOffset+40])
		}
	}
	if port := e.UDPSourcePort; port != nil {
		t.EntropyOffset, t.EntropyBase, t.EntropyCount = port.Offset, port.Base, port.Count
	}
	return nil
}
