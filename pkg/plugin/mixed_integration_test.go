package plugin

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestMixedPluginIntegration(t *testing.T) {
	const dir = "../../out/bin"
	if _, err := os.Stat(dir + "/mixed.go.wasm"); err != nil {
		t.Skip("build mixed.go first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	m, err := NewManager(dir, "", "go")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	if err := m.LoadPlugin(ctx, "mixed.go"); err != nil {
		t.Fatal(err)
	}
	wp, err := m.GetPlugin("mixed.go")
	if err != nil {
		t.Fatal(err)
	}
	gen := NewGeneratorAdapter("mixed.go", wp)
	if _, err := gen.Initialize(ctx, []byte(`{"plugin_config":null}`)); err != nil {
		t.Fatal(err)
	}
	r, err := gen.GenerateTemplate(ctx, map[string]interface{}{"device_mac_addr": []byte{2, 0, 0, 0, 0, 1}, "large_bytes": "18446744073709551615"})
	if err != nil {
		t.Fatal(err)
	}
	v := r.VariablePacketTemplate.Variants
	if len(v) != 2 || v[0].Base.Length < 64 || v[0].Weight != 3 || v[1].Kind != "tcp_flow" || len(v[1].TCPFlow.Flows) != 4 || v[1].TCPFlow.Flows[3].Bytes != "18446744073709551615" {
		t.Fatalf("response: %+v", r)
	}
}
