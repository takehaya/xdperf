package plugin

import (
	"context"
	"encoding/binary"
	"maps"
	"os"
	"testing"

	"go.uber.org/zap"
)

// TestSimpleUDPVLANIntegration loads the real simpleudp.go.wasm and checks that
// the optional outer 802.1Q tag (vlan_id) is emitted and shifts the UDP
// source-port sweep / checksum offsets, while vlan_id 0 stays untagged. It skips
// when the plugin has not been built (run `make build-plugins` first).
func TestSimpleUDPVLANIntegration(t *testing.T) {
	const pluginDir = "../../out/bin"
	if _, err := os.Stat(pluginDir + "/simpleudp.go.wasm"); err != nil {
		t.Skipf("plugin not built (run make build-plugins): %v", err)
	}

	ctx := context.Background()
	m, err := NewManager(pluginDir, "", "go", WithLogger(zap.NewNop()))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(ctx) })
	if err := m.LoadPlugin(ctx, "simpleudp.go"); err != nil {
		t.Fatalf("LoadPlugin: %v", err)
	}
	wp, err := m.GetPlugin("simpleudp.go")
	if err != nil {
		t.Fatalf("GetPlugin: %v", err)
	}
	gen := NewGeneratorAdapter("simpleudp.go", wp)

	base := map[string]any{
		"is_arp_resolve":  false,
		"dst_mac":         "aa:bb:cc:dd:ee:ff",
		"src_ip":          "192.168.1.1",
		"dst_ip":          "192.168.1.2",
		"payload_size":    64,
		"count":           1000,
		"device_mac_addr": []byte{0x02, 0, 0, 0, 0, 0x01},
		"device_name":     "lo",
	}
	variantOf := func(t *testing.T, in map[string]any) (data []byte, srcPortOff uint64, ipHdrOff uint16) {
		t.Helper()
		resp, err := gen.GenerateTemplate(ctx, in)
		if err != nil {
			t.Fatalf("GenerateTemplate: %v", err)
		}
		vs := resp.VariablePacketTemplate
		if len(vs.Variants) != 1 {
			t.Fatalf("variants = %d, want 1", len(vs.Variants))
		}
		v := vs.Variants[0]
		if len(v.Params) != 1 {
			t.Fatalf("params = %d, want 1 (src port sweep)", len(v.Params))
		}
		if len(v.Checksums) == 0 {
			t.Fatalf("expected an outer IPv4/UDP checksum spec")
		}
		return v.Base.Data, v.Params[0].ByteStart, v.Checksums[0].IPHeaderOffset
	}

	t.Run("untagged by default", func(t *testing.T) {
		d, srcPortOff, ipOff := variantOf(t, base)
		if et := binary.BigEndian.Uint16(d[12:14]); et != 0x0800 {
			t.Errorf("EtherType = 0x%04x, want 0x0800 (IPv4, untagged)", et)
		}
		if srcPortOff != 34 {
			t.Errorf("src port offset = %d, want 34 (untagged)", srcPortOff)
		}
		if ipOff != 14 {
			t.Errorf("outer IPv4 offset = %d, want 14 (untagged)", ipOff)
		}
	})

	t.Run("outer VLAN tag", func(t *testing.T) {
		in := map[string]any{"vlan_id": 100, "vlan_pcp": 3}
		maps.Copy(in, base)
		d, srcPortOff, ipOff := variantOf(t, in)
		if et := binary.BigEndian.Uint16(d[12:14]); et != 0x8100 {
			t.Errorf("EtherType = 0x%04x, want 0x8100 (802.1Q)", et)
		}
		tci := binary.BigEndian.Uint16(d[14:16])
		if vid := tci & 0x0FFF; vid != 100 {
			t.Errorf("VLAN VID = %d, want 100", vid)
		}
		if pcp := tci >> 13; pcp != 3 {
			t.Errorf("VLAN PCP = %d, want 3", pcp)
		}
		// Inner EtherType after the tag is IPv4.
		if et := binary.BigEndian.Uint16(d[16:18]); et != 0x0800 {
			t.Errorf("inner EtherType = 0x%04x, want 0x0800", et)
		}
		if srcPortOff != 38 {
			t.Errorf("src port offset = %d, want 38 (tagged, +4)", srcPortOff)
		}
		if ipOff != 18 {
			t.Errorf("outer IPv4 offset = %d, want 18 (tagged, +4)", ipOff)
		}
	})
}
