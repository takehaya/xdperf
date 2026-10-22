package xdperf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
)

// parseTCPBase accepts only headers whose mutable fields the engine owns.
// Length and checksum fields are placeholders; structural fields are checked.
func parseTCPBase(base guest.BasePacket) (*tcpTarget, error) {
	b := base.Data
	if len(b) != int(base.Length) || len(b) < 14 {
		return nil, fmt.Errorf("TCP base_packet length must equal data length and include Ethernet")
	}
	off, proto := 14, binary.BigEndian.Uint16(b[12:14])
	for n := 0; n < 2 && (proto == 0x8100 || proto == 0x88a8); n++ {
		if len(b) < off+4 {
			return nil, fmt.Errorf("truncated VLAN")
		}
		proto = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	t := &tcpTarget{srcMAC: append(net.HardwareAddr(nil), b[6:12]...), dstMAC: append(net.HardwareAddr(nil), b[:6]...), l3Off: uint16(off)}
	switch proto {
	case 0x0800:
		if len(b) < off+20 || b[off] != 0x45 || b[off+9] != 6 || binary.BigEndian.Uint16(b[off+6:])&0x3fff != 0 {
			return nil, fmt.Errorf("expected unfragmented IPv4 without options and TCP")
		}
		t.ipVersion = 4
		t.srcIP = append(net.IP(nil), b[off+12:off+16]...)
		t.dstIP = append(net.IP(nil), b[off+16:off+20]...)
		off += 20
	case 0x86dd:
		if len(b) < off+40 || b[off]>>4 != 6 || b[off+6] != 6 {
			return nil, fmt.Errorf("expected IPv6 without extensions and TCP")
		}
		t.ipVersion = 6
		t.srcIP = append(net.IP(nil), b[off+8:off+24]...)
		t.dstIP = append(net.IP(nil), b[off+24:off+40]...)
		off += 40
	default:
		return nil, fmt.Errorf("unsupported TCP base EtherType %#x (at most two VLAN tags)", proto)
	}
	if len(b) != off+20 {
		return nil, fmt.Errorf("TCP base_packet must end after the fixed TCP header; use syn_options/data_options")
	}
	t.l4Off, t.hdrLen = uint16(off), uint16(off+20)
	t.dstPort = binary.BigEndian.Uint16(b[off+2:])
	if t.dstPort == 0 || t.srcIP.IsUnspecified() || t.dstIP.IsUnspecified() || t.srcIP.IsMulticast() || t.dstIP.IsMulticast() {
		return nil, fmt.Errorf("TCP base requires unicast IP addresses and a nonzero destination port")
	}
	return t, nil
}

func tcpStaticOptions(input []byte, syn bool) ([]byte, error) {
	limit := 40
	if syn {
		limit -= tcpSynOptLen
	}
	if len(input) > limit {
		return nil, fmt.Errorf("TCP options exceed %d bytes", limit)
	}
	padding := byte(1)
	for i := 0; i < len(input); {
		kind := input[i]
		if kind == 0 {
			padding = 0
			for _, b := range input[i:] {
				if b != 0 {
					return nil, fmt.Errorf("nonzero TCP option padding after EOL")
				}
			}
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+2 > len(input) || input[i+1] < 2 || i+int(input[i+1]) > len(input) {
			return nil, fmt.Errorf("invalid TCP option length")
		}
		switch kind {
		case 2, 3, 5, 8, 19, 29, 30, 34:
			return nil, fmt.Errorf("TCP option kind %d is engine-owned or unsupported", kind)
		case 4:
			if !syn || input[i+1] != 2 {
				return nil, fmt.Errorf("SACK-Permitted requires SYN and length 2")
			}
		}
		i += int(input[i+1])
	}
	out := append([]byte(nil), input...)
	for len(out)%4 != 0 {
		out = append(out, padding)
	}
	return out, nil
}

func (x *Xdperf) templateMSS(t *tcpTarget, mss, options int) error {
	automatic := mss == 0
	if mss == 0 {
		mss = tcpDefaultMSSv4
		if t.ipVersion == 6 {
			mss = tcpDefaultMSSv6
		}
		ipLen := 20
		if t.ipVersion == 6 {
			ipLen = 40
		}
		mss -= int(t.l4Off) - 14 - ipLen
	}
	mss -= options
	max := x.Device.MTU + 14 - int(t.hdrLen) - options
	if automatic && mss > max {
		mss = max
	}
	if mss < tcpMinMSS || mss > max || int(t.hdrLen)+options+mss > x.getBpfConstant("max_packet_size") {
		return fmt.Errorf("TCP template MSS %d does not fit MTU/frame limits", mss)
	}
	t.mss = uint16(mss)
	return nil
}

// initTCPTemplates also handles destination-only groups for backwards compatibility.
func (x *Xdperf) initTCPTemplates(fallback *tcpTarget, frame []byte, cfg coreelf.BpfTcpCfg) error {
	for i, group := range x.mixed.groups {
		payload, err := tcpPayload(group.variant.TCPFlow.PayloadPattern)
		if err != nil {
			return err
		}
		if err := x.bpfobjs.TcpPayloadMap.Put(uint32(i), payload); err != nil {
			return err
		}
		count := uint32(1)
		if len(group.variant.Params) != 0 {
			count = group.count
		}
		state := newVariantState(group.variant.Params)
		for n := uint32(0); n < count; n++ {
			g := group
			if len(g.variant.Params) != 0 {
				g.variant, err = nextTCPFlowVariant(group.variant, state)
				if err != nil {
					return fmt.Errorf("TCP flow %d: %w", group.first+n, err)
				}
			}
			t, b := fallback, frame
			f := g.variant.TCPFlow
			if len(g.variant.Base.Data) != 0 {
				var err error
				t, err = parseTCPVariant(g.variant)
				if err != nil {
					return err
				}
				b = append([]byte(nil), g.variant.Base.Data...)
			} else if f.Destination != x.cfg.TCPDst || len(x.mixed.groups[0].variant.Base.Data) != 0 {
				copyCfg := x.cfg
				copyCfg.TCPDst, copyCfg.TCPMSS = f.Destination, g.mss
				resolver := &Xdperf{cfg: copyCfg, Device: x.Device, bpfSpec: x.bpfSpec, Logger: x.Logger}
				var err error
				t, err = resolver.resolveTCPTarget()
				if err != nil {
					return err
				}
				b, err = buildTCPTemplate(t, uint16(x.cfg.TCPPortBase))
				if err != nil {
					return err
				}
			}
			syn, err := tcpFlowOptions(f, true)
			if err != nil {
				return err
			}
			data, err := tcpFlowOptions(f, false)
			if err != nil {
				return err
			}
			extra := 0
			if f.Timestamps {
				extra = 12
			}
			tc := *t
			if err := x.templateMSS(&tc, g.mss, len(data)+extra); err != nil {
				return err
			}
			if x.Device != nil && int(tc.hdrLen)+tcpSynOptLen+len(syn)+extra > x.Device.MTU+14 {
				return fmt.Errorf("TCP SYN exceeds device MTU")
			}
			c := cfg
			c.WindowSegs, c.RtoNs, c.IpIdShared = uint32(g.window), uint64(g.rto), g.ipIDShared
			c.Mss, c.DstPort, c.HdrLen, c.L3Off, c.L4Off, c.IpVersion = tc.mss, tc.dstPort, tc.hdrLen, tc.l3Off, tc.l4Off, tc.ipVersion
			c.PseudoSum, c.SrcIp, c.DstIp = pseudoHeaderAddrSum(tc.srcIP, tc.dstIP), ipTo4Words(tc.srcIP), ipTo4Words(tc.dstIP)
			v := coreelf.BpfTcpTemplate{Cfg: c, SynLen: uint8(tcpSynOptLen + len(syn)), DataLen: uint8(len(data))}
			v.PayloadId = uint8(i)
			if f.Timestamps {
				v.Timestamps = 1
			}
			copy(v.Prefix[:], b[:tc.l4Off])
			copy(v.TcpHeader[:], b[tc.l4Off:tc.hdrLen])
			if tc.ipVersion == 4 {
				v.Prefix[tc.l3Off+1] &^= 3
			} else {
				v.Prefix[tc.l3Off+1] &^= 0x30
			}
			copy(v.SynOptions[:], []byte{2, 4, byte(tc.mss >> 8), byte(tc.mss), 1, 3, 3, 7})
			copy(v.SynOptions[8:], syn)
			copy(v.DataOptions[:], data)
			v.SynSum = tcpOptionSum(v.SynOptions[:])
			v.DataSum = tcpOptionSum(v.DataOptions[:])
			if f.Encapsulation != nil {
				if err := initTCPEncapsulation(&v, g.variant); err != nil {
					return err
				}
			}
			if err := x.bpfobjs.TcpTemplateMap.Put(group.templateID(group.first+n, i), v); err != nil {
				return fmt.Errorf("TCP template %d: %w", i, err)
			}
		}
	}
	return nil
}

func tcpOptionSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	return sum
}
