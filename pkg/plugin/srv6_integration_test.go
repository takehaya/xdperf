package plugin

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"go.uber.org/zap"
)

// TestSRv6PluginIntegration loads the real srv6.go.wasm through the host
// wazero runtime and runs plugin_process across the host<->guest JSON
// boundary. It guards the JSON contract (config field names) and the SRv6
// base-packet layout that the plugin's own builder unit tests cannot reach,
// since they take a Go struct rather than the JSON the host actually sends. It
// skips when the plugin has not been built (run `make build-plugins` first);
// no root required.
func TestSRv6PluginIntegration(t *testing.T) {
	const pluginDir = "../../out/bin"
	if _, err := os.Stat(pluginDir + "/srv6.go.wasm"); err != nil {
		t.Skipf("plugin not built (run make build-plugins): %v", err)
	}

	ctx := context.Background()
	m, err := NewManager(pluginDir, "", "go", WithLogger(zap.NewNop()))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(ctx) })

	if err := m.LoadPlugin(ctx, "srv6.go"); err != nil {
		t.Fatalf("LoadPlugin: %v", err)
	}
	wp, err := m.GetPlugin("srv6.go")
	if err != nil {
		t.Fatalf("GetPlugin: %v", err)
	}
	gen := NewGeneratorAdapter("srv6.go", wp)

	t.Run("l3vpn_ipv4", func(t *testing.T) {
		input := map[string]any{
			"is_arp_resolve":      false,
			"dst_mac":             "aa:bb:cc:dd:ee:ff",
			"src_ip":              "2001:db8::1",
			"mode":                "l3vpn_ipv4",
			"segments":            []string{"2001:db8:100::1", "2001:db8:200::1"},
			"flow_label_start":    0,
			"flow_label_end":      1000,
			"vary_inner_src_port": true,
			"imix_sizes":          []int{256, 768, 1400},
			"imix_weights":        []int{7, 2, 1},
			"count":               1000,
			"device_mac_addr":     []byte{0x02, 0, 0, 0, 0, 0x01},
			"device_name":         "lo",
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
			// Inner IPv4 header + inner UDP; the outer IPv6 has no checksum.
			if len(v.Checksums) != 2 {
				t.Errorf("variant %d: checksums = %d, want 2", i, len(v.Checksums))
			}
			// Flow label sweep + inner src port sweep enabled.
			if len(v.Params) != 2 {
				t.Errorf("variant %d: params = %d, want 2 (flow label + inner src port)", i, len(v.Params))
			}

			d := v.Base.Data
			if et := binary.BigEndian.Uint16(d[12:14]); et != 0x86DD {
				t.Errorf("variant %d: EtherType = 0x%04x, want 0x86DD (IPv6)", i, et)
			}
			if d[20] != 43 {
				t.Errorf("variant %d: IPv6 next header = %d, want 43 (routing)", i, d[20])
			}
			// SRH next header at 54 = 4 (IPv4-in-IPv6).
			if d[54] != 4 {
				t.Errorf("variant %d: SRH next header = %d, want 4", i, d[54])
			}
			// With dst_ip empty the outer destination is segments[0], the first
			// segment to visit. The SRH stores the list reversed, so that address
			// sits in the LAST wire slot (offset 78 with 2 segments) — the one
			// Segments Left (=1) points at — while slot 0 (offset 62) holds the
			// final segment segments[1].
			if string(d[38:54]) != string(d[78:94]) {
				t.Errorf("variant %d: outer dst != first-visited segment (last SRH slot)", i)
			}
			finalSeg := net.ParseIP("2001:db8:200::1").To16()
			if string(d[62:78]) != string(finalSeg) {
				t.Errorf("variant %d: SRH slot 0 != final segment", i)
			}

			if len(v.Params) == 2 {
				// Flow-label param: 4-byte diff over the version/TC/FL word at 14, with
				// the version prefix baked into the range.
				fl := v.Params[0]
				if fl.ByteStart != 14 || fl.ByteSize != 4 {
					t.Errorf("variant %d: flow label param = {%d,%d}, want {14,4}", i, fl.ByteStart, fl.ByteSize)
				}
				const prefix = uint64(6) << 28
				if fl.ByteRange.Start != prefix || fl.ByteRange.End != prefix|1000 {
					t.Errorf("variant %d: flow label range = {0x%x,0x%x}, want {0x%x,0x%x}",
						i, fl.ByteRange.Start, fl.ByteRange.End, prefix, prefix|1000)
				}
				// Inner UDP src: Eth(14)+IPv6(40)+SRH(8+2*16=40)+IPv4(20) = 114.
				if v.Params[1].ByteStart != 114 {
					t.Errorf("variant %d: inner port param ByteStart = %d, want 114", i, v.Params[1].ByteStart)
				}
			}
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		input := map[string]any{
			"is_arp_resolve":  false,
			"dst_mac":         "aa:bb:cc:dd:ee:ff",
			"src_ip":          "2001:db8::1",
			"mode":            "ipv6",
			"segments":        []string{"2001:db8:100::1"},
			"imix_sizes":      []int{256},
			"count":           1000,
			"device_mac_addr": []byte{0x02, 0, 0, 0, 0, 0x01},
			"device_name":     "lo",
		}

		resp, err := gen.GenerateTemplate(ctx, input)
		if err != nil {
			t.Fatalf("GenerateTemplate: %v", err)
		}
		vs := resp.VariablePacketTemplate
		if len(vs.Variants) != 1 {
			t.Fatalf("variants = %d, want 1", len(vs.Variants))
		}
		v := vs.Variants[0]
		// Inner UDP over the inner IPv6 pseudo header only.
		if len(v.Checksums) != 1 {
			t.Errorf("checksums = %d, want 1 (inner UDP over IPv6)", len(v.Checksums))
		}
		d := v.Base.Data
		// SRH next header = 41 (IPv6-in-IPv6).
		if d[54] != 41 {
			t.Errorf("SRH next header = %d, want 41", d[54])
		}
		// Inner IPv6 starts after Eth(14)+IPv6(40)+SRH(8+16=24) = 78.
		if d[78]>>4 != 6 {
			t.Errorf("inner IP version = %d, want 6", d[78]>>4)
		}
		if cs := v.Checksums[0]; cs.IPHeaderOffset != 78 {
			t.Errorf("UDP spec IPHeaderOffset = %d, want 78 (inner IPv6)", cs.IPHeaderOffset)
		}
	})
}
