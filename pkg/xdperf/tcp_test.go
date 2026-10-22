package xdperf

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// pseudoHeaderAddrSum must equal the address part of the RFC 793 pseudo
// header, i.e. what gopacket folds into a correct TCP checksum.
func TestPseudoHeaderAddrSum(t *testing.T) {
	src := net.ParseIP("192.168.1.10").To4()
	dst := net.ParseIP("10.0.0.1").To4()
	want := uint32(0xc0a8) + 0x010a + 0x0a00 + 0x0001
	if got := pseudoHeaderAddrSum(src, dst); got != want {
		t.Fatalf("v4 sum = %#x, want %#x", got, want)
	}
	src6 := net.ParseIP("fd00::1")
	dst6 := net.ParseIP("fd00::2")
	want6 := uint32(0xfd00) + 0x0001 + 0xfd00 + 0x0002
	if got := pseudoHeaderAddrSum(src6, dst6); got != want6 {
		t.Fatalf("v6 sum = %#x, want %#x", got, want6)
	}
}

func TestIPTo4Words(t *testing.T) {
	ip := net.ParseIP("10.1.2.3").To4()
	w := ipTo4Words(ip)
	if got := binary.NativeEndian.Uint32(ip); w[0] != got || w[1] != 0 {
		t.Fatalf("v4 words = %v", w)
	}
	ip6 := net.ParseIP("2001:db8::1")
	w6 := ipTo4Words(ip6)
	for i := 0; i < 4; i++ {
		if w6[i] != binary.NativeEndian.Uint32(ip6[i*4:]) {
			t.Fatalf("v6 word %d mismatch", i)
		}
	}
}

func TestBuildTCPTemplate(t *testing.T) {
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	cases := []struct {
		name string
		t    tcpTarget
	}{
		{"v4", tcpTarget{ipVersion: 4, srcIP: net.ParseIP("192.168.1.1").To4(), dstIP: net.ParseIP("192.168.1.2").To4(), dstPort: 5201, l3Off: 14, l4Off: 34, hdrLen: 54, mss: 100}},
		{"v6", tcpTarget{ipVersion: 6, srcIP: net.ParseIP("fd00::1"), dstIP: net.ParseIP("fd00::2"), dstPort: 5201, l3Off: 14, l4Off: 54, hdrLen: 74, mss: 100}},
		{"v4 vlan", tcpTarget{ipVersion: 4, srcIP: net.ParseIP("192.168.1.1").To4(), dstIP: net.ParseIP("192.168.1.2").To4(), dstPort: 5201, vlanID: 100, vlanPCP: 3, l3Off: 18, l4Off: 38, hdrLen: 58, mss: 100}},
		{"v6 vlan", tcpTarget{ipVersion: 6, srcIP: net.ParseIP("fd00::1"), dstIP: net.ParseIP("fd00::2"), dstPort: 5201, vlanID: 7, l3Off: 18, l4Off: 58, hdrLen: 78, mss: 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.t.srcMAC = mac("02:00:00:00:00:01")
			tc.t.dstMAC = mac("02:00:00:00:00:02")
			frame, err := buildTCPTemplate(&tc.t, 40000)
			if err != nil {
				t.Fatal(err)
			}
			if len(frame) != int(tc.t.hdrLen)+int(tc.t.mss) {
				t.Fatalf("len = %d, want %d", len(frame), int(tc.t.hdrLen)+int(tc.t.mss))
			}
			pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
			if el := pkt.ErrorLayer(); el != nil {
				t.Fatalf("decode error: %v", el.Error())
			}
			tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !ok {
				t.Fatal("no TCP layer")
			}
			if tcp.DataOffset != 5 || uint16(tcp.DstPort) != tc.t.dstPort || uint16(tcp.SrcPort) != 40000 {
				t.Fatalf("unexpected TCP header: %+v", tcp)
			}
			// the TCP header must start at l4Off: check the dst port bytes there
			if binary.BigEndian.Uint16(frame[tc.t.l4Off+2:]) != tc.t.dstPort {
				t.Fatalf("dst port not at l4Off %d", tc.t.l4Off)
			}
			if tc.t.vlanID != 0 {
				d, ok := pkt.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
				if !ok || d.VLANIdentifier != tc.t.vlanID || d.Priority != tc.t.vlanPCP {
					t.Fatalf("unexpected VLAN layer: %+v", d)
				}
			} else if pkt.Layer(layers.LayerTypeDot1Q) != nil {
				t.Fatal("unexpected VLAN tag")
			}
			for _, b := range frame[tc.t.hdrLen:] {
				if b != 0 {
					t.Fatal("payload must be all-zero (the data plane assumes it for checksums)")
				}
			}
		})
	}
}

func tcpServerTestConfig() Config {
	return Config{
		Device:      "lo",
		TCPServer:   true,
		TCPListen:   ":5201",
		TCPMaxConns: 1024,
		TCPAckEvery: 1,
		TCPRTO:      200 * time.Millisecond,
		Parallelism: 1,
		XDPMode:     "auto",
	}
}

func TestValidateTCPServer(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"ok", func(*Config) {}, false},
		{"ipv4 address", func(c *Config) { c.TCPListen = "10.0.0.2:5201" }, false},
		{"ipv6 any", func(c *Config) { c.TCPListen = "[::]:5201" }, false},
		{"with duration", func(c *Config) { c.Duration = time.Second }, false},
		{"swap-resp", func(c *Config) { c.SwapResp = true }, true},
		{"flow report needs TCP variants", func(c *Config) { c.TCPFlowReport = "flows.csv" }, true},
		{"rx-device", func(c *Config) { c.RxDevice = "eth1" }, true},
		{"count", func(c *Config) { c.Count = 10 }, true},
		{"infinite", func(c *Config) { c.Infinite = true }, true},
		{"bad listen", func(c *Config) { c.TCPListen = "5201" }, true},
		{"bad host", func(c *Config) { c.TCPListen = "example.com:5201" }, true},
		{"port zero", func(c *Config) { c.TCPListen = ":0" }, true},
		{"zero max conns", func(c *Config) { c.TCPMaxConns = 0 }, true},
		{"ack every too large", func(c *Config) { c.TCPAckEvery = 256 }, true},
		{"zero rto", func(c *Config) { c.TCPRTO = 0 }, true},
		{"mss below minimum", func(c *Config) { c.TCPMSS = 5 }, true},
		{"mss at minimum", func(c *Config) { c.TCPMSS = tcpMinMSS }, false},
		{"vlan id too large", func(c *Config) { c.TCPVlanID = 4095 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tcpServerTestConfig()
			tc.mutate(&c)
			c.Normalize()
			err := c.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNormalizeTCPServerImpliesReceiver(t *testing.T) {
	c := Config{TCPServer: true, Sender: true, PluginName: "ignored.go"}
	c.Normalize()
	if !c.Receiver || c.Sender {
		t.Fatalf("--tcp-server must imply receive-only mode, got sender=%v receiver=%v", c.Sender, c.Receiver)
	}
	if c.PluginLanguage != "" {
		t.Fatalf("plugin language must not be derived in TCP server mode, got %q", c.PluginLanguage)
	}
}

func TestParseTCPListen(t *testing.T) {
	cases := []struct {
		in      string
		wantIP  string
		wantAny bool
		wantV4  bool
		port    uint16
		wantErr bool
	}{
		{":5201", "0.0.0.0", true, true, 5201, false},
		{"0.0.0.0:80", "0.0.0.0", true, true, 80, false},
		{"10.1.2.3:5201", "10.1.2.3", false, true, 5201, false},
		{"[::]:5201", "::", true, false, 5201, false},
		{"[fd00::2]:5201", "fd00::2", false, false, 5201, false},
		{"fd00::2:5201", "", false, false, 0, true},
		{"10.1.2.3", "", false, false, 0, true},
		{":65536", "", false, false, 0, true},
		{"host:5201", "", false, false, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			ip, port, err := ParseTCPListen(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if ip.String() != tc.wantIP || port != tc.port || ip.IsUnspecified() != tc.wantAny || (ip.To4() != nil) != tc.wantV4 {
				t.Fatalf("got ip=%s port=%d any=%v v4=%v", ip, port, ip.IsUnspecified(), ip.To4() != nil)
			}
		})
	}
}
