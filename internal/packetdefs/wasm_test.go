package packetdefs

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func TestWasmCodecs(t *testing.T) {
	for _, name := range []string{"go", "tinygo"} {
		t.Run(name, func(t *testing.T) {
			path := "../../out/packetdefs/fixture." + name + ".wasm"
			data, err := os.ReadFile(path)
			if err != nil {
				if os.Getenv("XDPERF_REQUIRE_PACKETDEFS_WASM") == "1" {
					t.Fatal(err)
				}
				t.Skip("run make packetdefs-fixtures")
			}
			ctx := context.Background()
			r := wazero.NewRuntime(ctx)
			defer r.Close(ctx)
			wasi_snapshot_preview1.MustInstantiate(ctx, r)
			var stdout, stderr bytes.Buffer
			if _, err := r.InstantiateWithConfig(ctx, data, wazero.NewModuleConfig().WithStdout(&stdout).WithStderr(&stderr)); err != nil {
				t.Fatalf("%v\n%s", err, stderr.String())
			}
			if stdout.String() != "packetdefs ok\n" {
				t.Fatalf("stdout %q stderr %q", stdout.String(), stderr.String())
			}
		})
	}
}
