package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Go guests execute synchronously: the caller reads the buffered response only
// after the export returns. A second response must trap instead of blocking it.
func TestGoshimDuplicateResponses(t *testing.T) {
	for name, reply := range map[string]func(*GeneratorStack){
		"init":    func(s *GeneratorStack) { s.InitResponseChan = make(chan []byte, 1) },
		"process": func(s *GeneratorStack) { s.ProcessResponseChan = make(chan []byte, 1) },
		"cleanup": func(s *GeneratorStack) { s.CleanupResponseChan = make(chan []byte, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			s := &GeneratorStack{}
			reply(s)
			ctx := createContextWithStack(context.Background(), s)
			// Exercise the actual response callback using a small Wasm memory.
			r, mod := newGoshimTestMemory(t, ctx)
			defer r.Close(ctx)
			fn, ch := pluginInitResponseFn, s.InitResponseChan
			if name == "process" {
				fn, ch = pluginProcessResponseFn, s.ProcessResponseChan
			} else if name == "cleanup" {
				fn, ch = pluginCleanupResponseFn, s.CleanupResponseChan
			}
			fn(ctx, mod, []uint64{0, 0})
			done := make(chan any, 1)
			go func() {
				defer func() { done <- recover() }()
				fn(ctx, mod, []uint64{0, 0})
			}()
			select {
			case trap := <-done:
				if trap == nil {
					t.Fatal("duplicate response did not trap")
				}
			case <-time.After(time.Second):
				<-ch // release a regressed blocking callback before failing
				<-done
				t.Fatal("duplicate response blocked the host callback")
			}
		})
	}
}

func newGoshimTestMemory(t *testing.T, ctx context.Context) (wazero.Runtime, api.Module) {
	t.Helper()
	r := wazero.NewRuntime(ctx)
	mod, err := r.Instantiate(ctx, []byte{
		0, 97, 115, 109, 1, 0, 0, 0,
		5, 3, 1, 0, 1,
		7, 10, 1, 6, 'm', 'e', 'm', 'o', 'r', 'y', 2, 0,
	})
	if err != nil {
		_ = r.Close(ctx)
		t.Fatal(err)
	}
	return r, mod
}
