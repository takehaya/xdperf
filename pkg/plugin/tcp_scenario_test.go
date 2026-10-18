package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/tetratelabs/wazero"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestTCPScenarioResponseContract(t *testing.T) {
	valid := `{"template_type":"tcp_scenario","tcp_scenario":{"version":1,"flows":[{"bytes":"65536"}]}}`
	cases := []struct {
		name, data   string
		tcp, wantErr bool
	}{
		{"TCP", valid, true, false},
		{"wrong mode", valid, false, true},
		{"raw in TCP", `{"template_type":"raw","raw_packet_template":[]}`, true, true},
		{"variable in TCP", `{"template_type":"variable"}`, true, true},
		{"no body", `{"template_type":"tcp_scenario"}`, true, true},
		{"null body", `{"template_type":"tcp_scenario","tcp_scenario":null}`, true, true},
		{"wrong type", strings.Replace(valid, `"65536"`, `65536`, 1), true, true},
		{"unknown field", strings.Replace(valid, `"version":1`, `"version":1,"arrivals":[]`, 1), true, true},
		{"unknown flow field", strings.Replace(valid, `"bytes":`, `"typo":0,"bytes":`, 1), true, true},
		{"unknown envelope", strings.Replace(valid, `"template_type":`, `"typo":0,"template_type":`, 1), true, true},
		{"trailing JSON", valid + `{}`, true, true},
		{"mixed raw", strings.Replace(valid, `"tcp_scenario":{`, `"raw_packet_template":[{"length":1}],"tcp_scenario":{`, 1), true, true},
		{"mixed variable", strings.Replace(valid, `"tcp_scenario":{`, `"variable_packet_template":{"variants":[{}]},"tcp_scenario":{`, 1), true, true},
		{"mixed in packet mode", strings.Replace(valid, `"template_type":"tcp_scenario"`, `"template_type":"raw"`, 1), false, true},
		{"legacy raw", `{"template_type":"raw","raw_packet_template":[],"extra":true}`, false, false},
		{"legacy variable", `{"template_type":"variable","variable_packet_template":{"variants":[]}}`, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeGeneratorResponse([]byte(tc.data), tc.tcp)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
	boundary := append([]byte(valid), bytes.Repeat([]byte(" "), maxPluginOutputBytes-len(valid))...)
	if _, err := decodeGeneratorResponse(boundary, true); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeGeneratorResponse(append(boundary, ' '), true); err == nil {
		t.Fatal("accepted oversized response")
	}
}

// The tiny module exports a 33 MiB linear memory, allowing host ABI boundary
// checks without allocating a second full Go runtime in Wasm.
func TestGoshimResponseLimitAndRequestRetry(t *testing.T) {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	mod, err := r.Instantiate(ctx, []byte{
		0, 97, 115, 109, 1, 0, 0, 0,
		5, 4, 1, 0, 0x90, 4, // memory minimum 528 pages
		7, 10, 1, 6, 'm', 'e', 'm', 'o', 'r', 'y', 2, 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	mem := mod.Memory()
	request := bytes.Repeat([]byte("x"), 4096)
	if got := writeBytesIfUnderLimit(mem, request, 0, 2048); got != 4096 {
		t.Fatalf("needed length = %d", got)
	}
	if got := writeBytesIfUnderLimit(mem, request, 0, 4096); got != 4096 {
		t.Fatalf("retry length = %d", got)
	}
	b, _ := mem.Read(0, 4096)
	if !bytes.Equal(b, request) {
		t.Fatal("request retry lost bytes")
	}
	stack := &GeneratorStack{}
	ctx = createContextWithStack(ctx, stack)
	pluginProcessResponseFn(ctx, mod, []uint64{0, maxPluginOutputBytes})
	if len(stack.GeneratorProcessResponse) != maxPluginOutputBytes {
		t.Fatal("response at limit rejected")
	}
	mem.WriteByte(0, 'z')
	if stack.GeneratorProcessResponse[0] != 'x' {
		t.Fatal("response aliases guest memory")
	}
	defer func() {
		if recover() == nil {
			t.Error("oversized Go response accepted")
		}
	}()
	pluginProcessResponseFn(ctx, mod, []uint64{0, maxPluginOutputBytes + 1})
}

func TestHeavyHitterPluginIntegration(t *testing.T) {
	const dir = "../../out/bin"
	if _, err := os.Stat(dir + "/heavyhitter.go.wasm"); err != nil {
		t.Skipf("build heavyhitter.go first: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logs, observed := observer.New(zap.InfoLevel)
	m, err := NewManager(dir, "", "go", WithLogger(zap.New(logs)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err := m.LoadPlugin(ctx, "heavyhitter.go"); err != nil {
		t.Fatal(err)
	}
	wp, err := m.GetPlugin("heavyhitter.go")
	if err != nil {
		t.Fatal(err)
	}
	gen := NewGeneratorAdapter("heavyhitter.go", wp)
	out, err := gen.Initialize(ctx, []byte(`{"plugin_config":null}`))
	if err != nil {
		t.Fatal(err)
	}
	var init guest.GeneratorInitResponse
	if err := json.Unmarshal(out, &init); err != nil || !init.Success {
		t.Fatalf("init: %s, %v", out, err)
	}
	req := guest.TCPScenarioRequest{
		Mode: "tcp_scenario", SupportedVersions: []int{1}, Capabilities: []string{"static_flows", "zero_payload"}, DeviceName: "lo",
		Limits: guest.TCPScenarioLimits{MaxSlots: 4, MaxEndpoints: 1, MaxResponseBytes: maxPluginOutputBytes},
		Config: map[string]interface{}{"address": "2001:db8::2", "port": 5202, "seed": "18446744073709551615", "padding": strings.Repeat("x", 4096)},
	}
	s, err := gen.GenerateTCPScenario(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Flows) != 4 || s.Endpoints[0].Address != "2001:db8::2" || s.Endpoints[0].Port != 5202 || s.Seed != "18446744073709551615" {
		t.Fatalf("scenario = %+v", s)
	}
	for i, f := range s.Flows {
		want := "65536"
		if i == 3 {
			want = "67108864"
		}
		if f.Bytes != want || f.StartNS != "0" {
			t.Fatalf("flow %d = %+v", i, f)
		}
	}
	// Manager owns cleanup. Unload followed by Close must call it exactly once.
	if err := m.UnloadPlugin(ctx, "heavyhitter.go"); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range observed.All() {
		if strings.Contains(entry.Message, "heavyhitter cleanup") {
			count++
		}
		for _, field := range entry.Context {
			if field.String == "heavyhitter cleanup" {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("cleanup log count = %d, want 1; logs = %+v", count, observed.All())
	}
}

func TestPluginExecutionDeadline(t *testing.T) {
	m, err := NewManager(t.TempDir(), "", "go")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	// (func (export "plugin_process") (param i32 i32 i32 i32) (result i32)
	//   (loop (br 0)) (i32.const 0))
	mod, err := m.runtime.Instantiate(context.Background(), []byte{
		0, 97, 115, 109, 1, 0, 0, 0,
		1, 9, 1, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
		3, 2, 1, 0,
		7, 18, 1, 14, 'p', 'l', 'u', 'g', 'i', 'n', '_', 'p', 'r', 'o', 'c', 'e', 's', 's', 0, 0,
		10, 11, 1, 9, 0, 3, 0x40, 0x0c, 0, 0x0b, 0x41, 0, 0x0b,
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &wasmPlugin{module: mod, pluginLang: "go", wasiP1HostModule: m.wasiP1HostModule}
	p.functions.process = mod.ExportedFunction("plugin_process")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.CallProcess(ctx, []byte(`{}`)); err == nil {
		t.Fatal("infinite guest execution succeeded")
	}
	if ctx.Err() != context.DeadlineExceeded || !mod.IsClosed() {
		t.Fatalf("deadline did not close module: %v", ctx.Err())
	}
}
