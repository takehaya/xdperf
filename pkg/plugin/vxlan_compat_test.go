package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// TestVXLANByteCompatibility compares the complete decoded JSON response,
// including every packet byte, against output captured before C-to-Go migration
// at 7b16bbc. The fixture is deliberately independent of generated definitions.
func TestVXLANByteCompatibility(t *testing.T) {
	if _, err := os.Stat("../../out/bin/vxlan.go.wasm"); err != nil {
		t.Skip("build vxlan.go first")
	}
	ctx := context.Background()
	m, err := NewManager("../../out/bin", "", "go", WithLogger(zap.NewNop()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(ctx) })
	if err := m.LoadPlugin(ctx, "vxlan.go"); err != nil {
		t.Fatal(err)
	}
	wp, err := m.GetPlugin("vxlan.go")
	if err != nil {
		t.Fatal(err)
	}
	gen := NewGeneratorAdapter("vxlan.go", wp)
	for i, patch := range []map[string]any{
		{}, {"dst_port": nil}, {"dst_port": 0}, {"dst_port": 8472},
		{"vlan_id": 123, "vlan_pcp": 5, "inner_udp_checksum": true, "vary_inner_ip": true, "vary_outer_port": true},
		{"inner_mode": "l2only", "imix_sizes": []int{64, 128}, "vary_inner_port": true, "vary_inner_ip": true},
		{"vni_start": 0, "vni_end": 0, "inner_udp_checksum": true},
		{"vni_start": 16777215, "vni_end": 16777215, "vlan_id": 4094},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			input := map[string]any{"is_arp_resolve": false, "dst_mac": "aa:bb:cc:dd:ee:ff", "device_mac_addr": []byte{2, 0, 0, 0, 0, 1}, "device_name": "lo", "vni_start": 100, "vni_end": 200, "vary_inner_port": true, "imix_sizes": []int{128}, "imix_weights": []int{7}}
			for k, v := range patch {
				input[k] = v
			}
			resp, err := gen.GenerateTemplate(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			name := filepath.Join("testdata", "vxlan_before", fmt.Sprintf("%d.json", i))
			want, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if string(want) != string(got) {
				t.Fatalf("VXLAN output differs from pre-migration fixture %s", name)
			}
		})
	}
}
