package plugin

import (
	"bytes"
	"context"
	"github.com/tetratelabs/wazero"
	"testing"
	"time"
)

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
