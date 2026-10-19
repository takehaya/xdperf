package main

import (
	"io"
	"testing"

	"github.com/takehaya/xdperf/pkg/xdperf"
	"github.com/urfave/cli"
)

func TestTCPPluginSelection(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		plugin  string
		wantErr bool
	}{
		{"legacy TCP", []string{"--tcp", "--tcp-dst", "192.0.2.1:5201", "--tcp-bytes", "1k"}, "", false},
		{"removed scenario", []string{"--tcp", "--plugin", "mixed.go"}, "", true},
		{"short plugin flag", []string{"--tcp", "-p", "mixed.go"}, "", true},
		{"explicit default flows", []string{"--tcp", "--plugin", "mixed.go", "--tcp-flows", "1"}, "", true},
		{"explicit zero bytes", []string{"--tcp", "--plugin", "mixed.go", "--tcp-bytes", "0"}, "", true},
		{"conflicting dst", []string{"--tcp", "--plugin", "mixed.go", "--tcp-dst", "192.0.2.1:5201"}, "", true},
		{"packet mode default", []string{"--count", "1k"}, "simpleudp.tinygo", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newApp("test")
			app.Writer, app.ErrWriter = io.Discard, io.Discard
			var cfg xdperf.Config
			app.Commands[0].Action = func(ctx *cli.Context) error {
				var err error
				cfg, err = ParseArgs(ctx)
				return err
			}
			err := app.Run(append([]string{"xdperf", "run", "--device", "lo"}, tc.args...))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil && cfg.PluginName != tc.plugin {
				t.Fatalf("plugin = %q, want %q", cfg.PluginName, tc.plugin)
			}
			if err == nil && tc.plugin == "mixed.go" && cfg.PluginLanguage != "go" {
				t.Fatalf("language = %q", cfg.PluginLanguage)
			}
		})
	}
}
