package plugin

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"go.uber.org/zap"
)

// TestVXLANPluginIntegration loads the real vxlan.go.wasm through the host
// wazero runtime and runs plugin_process across the host<->guest JSON boundary.
// It guards the JSON contract (config field names) and the VXLAN base-packet
// layout that the plugin's own builder unit tests cannot reach, since they take
// a Go struct rather than the JSON the host actually sends. It skips when the
// plugin has not been built (run `make build-plugins` first); no root required.
func TestVXLANPluginIntegration(t *testing.T) {
	const pluginDir = "../../out/bin"
	if _, err := os.Stat(pluginDir + "/vxlan.go.wasm"); err != nil {
		t.Skipf("plugin not built (run make build-plugins): %v", err)
	}

	ctx := context.Background()
	m, err := NewManager(pluginDir, "", "go", WithLogger(zap.NewNop()))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(ctx) })

	if err := m.LoadPlugin(ctx, "vxlan.go"); err != nil {
		t.Fatalf("LoadPlugin: %v", err)
	}
	wp, err := m.GetPlugin("vxlan.go")
	if err != nil {
		t.Fatalf("GetPlugin: %v", err)
	}
	gen := NewGeneratorAdapter("vxlan.go", wp)

	input := map[string]any{
		"is_arp_resolve":  false,
		"dst_mac":         "aa:bb:cc:dd:ee:ff",
		"src_ip":          "10.0.0.1",
		"dst_ip":          "10.0.0.2",
		"vni_start":       100,
		"vni_end":         200,
		"inner_src_ip":    "192.168.0.1",
		"inner_dst_ip":    "192.168.0.2",
		"vary_inner_port": true,
		"imix_sizes":      []int{128, 768, 1400},
		"imix_weights":    []int{7, 2, 1},
		"count":           1000,
		"device_mac_addr": []byte{0x02, 0, 0, 0, 0, 0x01},
		"device_name":     "lo",
	}

	resp, err := gen.GenerateTemplate(ctx, input)
	if err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}
	if resp.TemplateType != "variable" {
		t.Fatalf("template type = %q, want variable", resp.TemplateType)
	}
	vs := resp.VariablePacketTemplate
	if len(vs.Variants) != 3 {
		t.Fatalf("variants = %d, want 3 (one per imix size)", len(vs.Variants))
	}
	for i, v := range vs.Variants {
		// Default inner UDP checksum is disabled, so no inner UDP spec:
		// [outer IPv4, inner IPv4].
		if len(v.Checksums) != 2 {
			t.Errorf("variant %d: checksums = %d, want 2", i, len(v.Checksums))
		}
		// VNI sweep + inner UDP port sweep enabled.
		if len(v.Params) != 2 {
			t.Errorf("variant %d: params = %d, want 2 (VNI + inner port)", i, len(v.Params))
		}

		d := v.Base.Data
		// Outer UDP dst port = VXLAN 4789.
		if dport := binary.BigEndian.Uint16(d[36:38]); dport != 4789 {
			t.Errorf("variant %d: outer UDP dst port = %d, want 4789", i, dport)
		}
		// Outer UDP checksum must be 0 (RFC 7348).
		if d[40] != 0 || d[41] != 0 {
			t.Errorf("variant %d: outer UDP checksum = 0x%02x%02x, want 0", i, d[40], d[41])
		}
		// VXLAN flags: I bit set.
		if d[42] != 0x08 {
			t.Errorf("variant %d: VXLAN flags = 0x%02x, want 0x08", i, d[42])
		}
		// VNI 24-bit at 46..48 = vni_start (100).
		vni := uint32(d[46])<<16 | uint32(d[47])<<8 | uint32(d[48])
		if vni != 100 {
			t.Errorf("variant %d: base VNI = %d, want vni_start 100", i, vni)
		}

		// Variable params target the VNI (4-byte diff starting at the reserved byte
		// 45, so the 24-bit VNI at 46..48 is covered) and inner UDP src (offset 84).
		if len(v.Params) == 2 {
			if v.Params[0].ByteStart != 45 || v.Params[0].ByteSize != 4 {
				t.Errorf("variant %d: VNI param = {%d,%d}, want {45,4}", i, v.Params[0].ByteStart, v.Params[0].ByteSize)
			}
			if v.Params[1].ByteStart != 84 {
				t.Errorf("variant %d: inner port param ByteStart = %d, want 84", i, v.Params[1].ByteStart)
			}
		}
	}
}
