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
	// Race-instrumented WASM compilation can exceed 30 seconds on CI.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	r, err := gen.GenerateTemplate(ctx, map[string]interface{}{"device_mac_addr": []byte{2, 0, 0, 0, 0, 1}, "large_bytes": "18446744073709551615", "window_segs": 7, "mss": 900})
	if err != nil {
		t.Fatal(err)
	}
	v := r.VariablePacketTemplate.Variants
	if len(v) != 2 || v[0].Base.Length < 64 || v[0].Weight != 3 || v[1].Kind != "tcp_flow" || len(v[1].TCPFlow.Flows) != 4 || v[1].TCPFlow.Flows[3].Bytes != "18446744073709551615" || v[1].TCPFlow.WindowSegs != 7 || v[1].TCPFlow.MSS != 900 {
		t.Fatalf("response: %+v", r)
	}
	r, err = gen.GenerateTemplate(ctx, map[string]interface{}{
		"device_mac_addr": []byte{2, 0, 0, 0, 0, 1},
		"tcp_base":        map[string]interface{}{"data": []byte{1, 2, 3, 4}, "length": 4},
		"syn_options":     []byte{4, 2, 1, 1}, "data_options": []byte{1, 1, 1, 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	tcp := r.VariablePacketTemplate.Variants[1]
	if tcp.Base.Length != 4 || len(tcp.Base.Data) != 4 || tcp.TCPFlow.Destination != "" || len(tcp.TCPFlow.SynOptions) != 4 || len(tcp.TCPFlow.DataOptions) != 4 {
		t.Fatalf("template fields lost: %+v", tcp)
	}

	t.Run("tcpflow knobs", func(t *testing.T) {
		if _, err := os.Stat(dir + "/tcpflow.go.wasm"); err != nil {
			t.Skip("build tcpflow.go first")
		}
		if err := m.LoadPlugin(ctx, "tcpflow.go"); err != nil {
			t.Fatal(err)
		}
		wp, err := m.GetPlugin("tcpflow.go")
		if err != nil {
			t.Fatal(err)
		}
		gen := NewGeneratorAdapter("tcpflow.go", wp)
		if _, err := gen.Initialize(ctx, []byte(`{"plugin_config":null}`)); err != nil {
			t.Fatal(err)
		}
		r, err := gen.GenerateTemplate(ctx, map[string]interface{}{
			"window_segs": 3, "mss": 768, "rto_ms": 75, "ip_id": "flow", "port_base": 12001,
		})
		if err != nil {
			t.Fatal(err)
		}
		set := r.VariablePacketTemplate
		f := set.Variants[0].TCPFlow
		if set.TCPPortBase != 12001 || f.WindowSegs != 3 || f.MSS != 768 || f.RTOMillis != 75 || f.IPID != "flow" {
			t.Fatalf("tcpflow knobs lost: %+v / %+v", set, f)
		}
	})

}
