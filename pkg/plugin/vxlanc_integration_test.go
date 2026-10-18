package plugin

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

// TestVXLANCPluginIntegration loads vxlan.c.wasm, a plugin written in C and
// built freestanding for wasm32, through the same non-Go ABI the TinyGo
// plugins use. It checks the JSON contract and that the base packet decodes as
// VXLAN with valid IPv4 checksums and an inner source-port sweep. It skips when
// the plugin has not been built (make -C plugins/vxlan.c).
func TestVXLANCPluginIntegration(t *testing.T) {
	const pluginDir = "../../out/bin"
	if _, err := os.Stat(pluginDir + "/vxlan.c.wasm"); err != nil {
		t.Skipf("plugin not built (make -C plugins/vxlan.c): %v", err)
	}

	ctx := context.Background()
	m, err := NewManager(pluginDir, "", "c", WithLogger(zap.NewNop()))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(ctx) })
	if err := m.LoadPlugin(ctx, "vxlan.c"); err != nil {
		t.Fatalf("LoadPlugin: %v", err)
	}
	wp, err := m.GetPlugin("vxlan.c")
	if err != nil {
		t.Fatalf("GetPlugin: %v", err)
	}
	gen := NewGeneratorAdapter("vxlan.c", wp)
	if _, err := gen.Initialize(ctx, []byte(`{}`)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	input := map[string]any{
		"src_mac":      "02:00:00:00:00:01",
		"dst_mac":      "aa:bb:cc:dd:ee:ff",
		"src_ip":       "10.0.0.1",
		"dst_ip":       "10.0.0.2",
		"vni":          4242,
		"inner_src_ip": "192.168.0.1",
		"inner_dst_ip": "192.168.0.2",
		"inner_flows":  16384,
		"count":        1000,
		"device_name":  "lo",
	}
	// Repeated calls must rewind the bump allocator. String values matching
	// config keys (or containing escaped quotes) must not shadow actual keys.
	for i, device := range []string{"lo", "vni", "src_ip", "inner_src_ip", `ignored "vni":0`} {
		input["device_name"] = device
		r, err := gen.GenerateTemplate(ctx, input)
		if err != nil {
			t.Fatalf("GenerateTemplate #%d: %v", i, err)
		}
		if r.TemplateType != "variable" || len(r.VariablePacketTemplate.Variants) != 1 {
			t.Fatalf("template %q with %d variants", r.TemplateType, len(r.VariablePacketTemplate.Variants))
		}
		v := r.VariablePacketTemplate.Variants[0]
		if int(v.Base.Length) != len(v.Base.Data) || len(v.Base.Data) != 50+14+20+8+18 {
			t.Fatalf("length %d, data %d", v.Base.Length, len(v.Base.Data))
		}
		pkt := gopacket.NewPacket(v.Base.Data, layers.LayerTypeEthernet, gopacket.Default)
		vx, ok := pkt.Layer(layers.LayerTypeVXLAN).(*layers.VXLAN)
		if !ok || !vx.ValidIDFlag || vx.VNI != 4242 {
			t.Fatalf("VXLAN layer: %+v", pkt.Layer(layers.LayerTypeVXLAN))
		}
		var ips []*layers.IPv4
		for _, l := range pkt.Layers() {
			if ip, ok := l.(*layers.IPv4); ok {
				ips = append(ips, ip)
			}
		}
		if len(ips) != 2 || ips[1].SrcIP.String() != "192.168.0.1" {
			t.Fatalf("IPv4 layers: %d", len(ips))
		}
		for j, ip := range ips {
			want := ip.Checksum
			if err := ip.SerializeTo(gopacket.NewSerializeBuffer(), gopacket.SerializeOptions{ComputeChecksums: true}); err != nil {
				t.Fatal(err)
			}
			if ip.Checksum != want {
				t.Errorf("IPv4 #%d checksum %#04x, want %#04x", j, want, ip.Checksum)
			}
		}
		if len(v.Params) != 1 || v.Params[0].ByteStart != 84 || v.Params[0].ByteSize != 2 ||
			v.Params[0].ByteRange.Start != 10000 || v.Params[0].ByteRange.End != 10000+16383 {
			t.Fatalf("params %+v", v.Params)
		}
	}

	for _, tc := range []struct {
		name  string
		key   string
		value any
	}{
		{"short MAC", "src_mac", "02"},
		{"long MAC", "src_mac", "02:00:00:00:00:01:ff"},
		{"truncated MAC", "src_mac", "02:00:00:00:00:01" + strings.Repeat("a", 40)},
		{"IPv4 overflow", "src_ip", "4294967297.0.0.1"},
		{"negative port", "src_port", -1},
		{"fractional port", "src_port", 1.5},
		{"string port", "src_port", "49152"},
		{"integer overflow", "vni", json.Number("18446744073709551616")},
		{"flow range overflow", "inner_flows", ^uint64(0)},
		{"base range overflow", "inner_sport_base", ^uint64(0)},
		{"empty flow range", "inner_flows", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := maps.Clone(input)
			invalid[tc.key] = tc.value
			if _, err := gen.GenerateTemplate(ctx, invalid); err == nil {
				t.Fatalf("invalid %s accepted: %v", tc.key, tc.value)
			}
		})
	}

	// Missing required keys are reported, not turned into a bogus packet.
	if _, err := gen.GenerateTemplate(ctx, map[string]any{"count": 1}); err == nil {
		t.Fatal("missing config accepted")
	}
}
