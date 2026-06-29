package plugin

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"go.uber.org/zap"
)

// TestGTPv1UPluginIntegration loads the real gtpv1u.go.wasm through the host
// wazero runtime and runs plugin_process across the host<->guest JSON boundary.
// It guards the JSON contract (config field names) and the GTP-U base-packet
// layout that the plugin's own builder unit tests cannot reach, since they take
// a Go struct rather than the JSON the host actually sends. It skips when the
// plugin has not been built (run `make build-plugins` first); no root required.
func TestGTPv1UPluginIntegration(t *testing.T) {
	const pluginDir = "../../out/bin"
	if _, err := os.Stat(pluginDir + "/gtpv1u.go.wasm"); err != nil {
		t.Skipf("plugin not built (run make build-plugins): %v", err)
	}

	ctx := context.Background()
	m, err := NewManager(pluginDir, "", "go", WithLogger(zap.NewNop()))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(ctx) })

	if err := m.LoadPlugin(ctx, "gtpv1u.go"); err != nil {
		t.Fatalf("LoadPlugin: %v", err)
	}
	wp, err := m.GetPlugin("gtpv1u.go")
	if err != nil {
		t.Fatalf("GetPlugin: %v", err)
	}
	gen := NewGeneratorAdapter("gtpv1u.go", wp)

	input := map[string]any{
		"is_arp_resolve":  false,
		"dst_mac":         "aa:bb:cc:dd:ee:ff",
		"src_ip":          "10.0.0.1",
		"dst_ip":          "10.0.0.2",
		"teid_start":      1,
		"teid_end":        1000,
		"enable_psc":      true,
		"qfi_start":       1,
		"qfi_end":         9,
		"inner_src_ip":    "192.168.0.1",
		"inner_dst_ip":    "192.168.0.2",
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
		// [outer IPv4, inner IPv4, outer UDP].
		if len(v.Checksums) != 3 {
			t.Errorf("variant %d: checksums = %d, want 3", i, len(v.Checksums))
		}
		if len(v.Params) != 2 { // TEID + QFI
			t.Errorf("variant %d: params = %d, want 2 (TEID+QFI)", i, len(v.Params))
		}

		d := v.Base.Data
		// Inner UDP checksum is disabled by default (5G inner UDP at offset 78).
		if d[84] != 0 || d[85] != 0 {
			t.Errorf("variant %d: inner UDP checksum = 0x%02x%02x, want 0 (disabled)", i, d[84], d[85])
		}
		if d[42] != 0x34 {
			t.Errorf("variant %d: GTP flags = 0x%02x, want 0x34 (ver1,PT,E)", i, d[42])
		}
		if d[43] != 0xFF {
			t.Errorf("variant %d: GTP msg type = 0x%02x, want 0xFF (G-PDU)", i, d[43])
		}
		if dport := binary.BigEndian.Uint16(d[36:38]); dport != 2152 {
			t.Errorf("variant %d: outer UDP dst port = %d, want 2152", i, dport)
		}
		if teid := binary.BigEndian.Uint32(d[46:50]); teid != 1 {
			t.Errorf("variant %d: base TEID = %d, want teid_start 1", i, teid)
		}
		if d[56] != 1 {
			t.Errorf("variant %d: base QFI byte = %d, want qfi_start 1", i, d[56])
		}

		// The variable params must target the TEID (offset 46) and QFI (offset 56).
		if len(v.Params) == 2 {
			if v.Params[0].ByteStart != 46 {
				t.Errorf("variant %d: TEID param ByteStart = %d, want 46", i, v.Params[0].ByteStart)
			}
			if v.Params[1].ByteStart != 56 {
				t.Errorf("variant %d: QFI param ByteStart = %d, want 56", i, v.Params[1].ByteStart)
			}
		}
	}
}
