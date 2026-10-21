package main

import (
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/xdperf/pkg/logger"
	"github.com/takehaya/xdperf/pkg/xdperf"
	"github.com/urfave/cli"
)

func TestTCPPluginSelection(t *testing.T) {
	clearConfigEnv(t)
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

func TestDurationPacketBudget(t *testing.T) {
	clearConfigEnv(t)
	tests := []struct {
		name, duration, pps string
		wantCount           uint64
		wantErr             string
	}{
		{name: "batch remainder", duration: "1.28005s", pps: "20k", wantCount: 25601},
		{name: "290ms regression", duration: "290ms", pps: "100", wantCount: 29},
		{name: "2.3s regression", duration: "2.3s", pps: "100k", wantCount: 230000},
		{name: "2.01s regression", duration: "2.01s", pps: "100", wantCount: 201},
		{name: "fractional packet", duration: "299ms", pps: "100", wantCount: 29},
		{name: "zero budget", duration: "5ms", pps: "100", wantErr: "calculated count must be greater than zero"},
		{name: "uint64 limit", duration: "1s", pps: "18446744073709551615", wantCount: math.MaxUint64},
		{name: "wide intermediate", duration: "500ms", pps: "18446744073709551615", wantCount: math.MaxUint64 / 2},
		{name: "overflow", duration: "2s", pps: "18446744073709551615", wantErr: "calculated count exceeds uint64 range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseRunArgs("--device", "lo", "--duration", tt.duration, "--pps", tt.pps)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Count != tt.wantCount {
				t.Fatalf("duration budget = %d, want %d", cfg.Count, tt.wantCount)
			}
		})
	}
}

func TestReceiverIgnoresPacketBudget(t *testing.T) {
	clearConfigEnv(t)
	tests := []struct {
		name string
		args []string
	}{
		{name: "zero duration budget", args: []string{"--duration", "5ms", "--pps", "100"}},
		{name: "overflowing duration budget", args: []string{"--duration", "2s", "--pps", "18446744073709551615"}},
		{name: "duration budget below parallelism", args: []string{"--duration", "15ms", "--pps", "100", "--parallelism", "2"}},
		{name: "explicit count below parallelism", args: []string{"--count", "1", "--parallelism", "2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"--device", "lo", "--send=false", "--recv"}, tt.args...)
			if _, err := parseRunArgs(args...); err != nil {
				t.Fatalf("receiver-only config rejected: %v", err)
			}
		})
	}
}

// Isolate parsing tests from the caller's configuration, including logger settings.
func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "XDPERF_") {
			t.Setenv(key, value) // Restore the original value when the test ends.
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// Replace only the action: exercise the real command flags without loading eBPF.
func parseRunArgs(args ...string) (xdperf.Config, error) {
	app := newApp("test")
	app.Writer, app.ErrWriter = io.Discard, io.Discard
	var cfg xdperf.Config
	app.Commands[0].Action = func(ctx *cli.Context) error {
		var err error
		cfg, err = ParseArgs(ctx)
		return err
	}
	err := app.Run(append([]string{"xdperf", "run"}, args...))
	return cfg, err
}

func TestParseArgsEnvPrecedence(t *testing.T) {
	clearConfigEnv(t)
	cases := []struct {
		flag, env, envValue, flagValue string
		field                          func(xdperf.Config) any
		defaultWant, envWant, flagWant any
	}{
		{"plugin", "XDPERF_PLUGIN", "mixed.go", "vxlan.c", func(c xdperf.Config) any { return c.PluginName }, "simpleudp.tinygo", "mixed.go", "vxlan.c"},
		{"plugin-path", "XDPERF_PLUGIN_PATH", "/env/plugins", "/cli/plugins", func(c xdperf.Config) any { return c.PluginPath }, "/usr/local/share/xdperf/plugins", "/env/plugins", "/cli/plugins"},
		{"plugin-config", "XDPERF_PLUGIN_CONFIG", `{"size":128}`, `{"size":256}`, func(c xdperf.Config) any { return c.PluginConfig }, "", `{"size":128}`, `{"size":256}`},
		{"send", "XDPERF_SEND", "false", "true", func(c xdperf.Config) any { return c.Sender }, true, false, true},
		{"swap-resp", "XDPERF_SWAP_RESP", "true", "false", func(c xdperf.Config) any { return c.SwapResp }, false, true, false},
		{"count", "XDPERF_COUNT", "2k", "3k", func(c xdperf.Config) any { return c.Count }, uint64(0), uint64(2000), uint64(3000)},
		{"pps", "XDPERF_PPS", "10k", "20k", func(c xdperf.Config) any { return c.PPS }, uint64(0), uint64(10000), uint64(20000)},
		{"debugmode", "XDPERF_DEBUGMODE", "1", "0", func(c xdperf.Config) any { return c.LoggerConfig.Verbose }, 0, 1, 0},
		{"batch-size", "XDPERF_BATCH_SIZE", "32", "16", func(c xdperf.Config) any { return c.BatchSize }, uint32(64), uint32(32), uint32(16)},
		{"cpu-mode", "XDPERF_CPU_MODE", "local", "balanced", func(c xdperf.Config) any { return c.CPUMode }, "auto", "local", "balanced"},
		{"xdp-mode", "XDPERF_XDP_MODE", "generic", "native", func(c xdperf.Config) any { return c.XDPMode }, "auto", "generic", "native"},
		{"otlp-interval", "XDPERF_OTLP_INTERVAL", "5s", "2s", func(c xdperf.Config) any { return c.OTLPInterval }, 10 * time.Second, 5 * time.Second, 2 * time.Second},
		{"otlp-insecure", "XDPERF_OTLP_INSECURE", "true", "false", func(c xdperf.Config) any { return c.OTLPInsecure }, false, true, false},
		{"tcp-flow-report", "XDPERF_TCP_FLOW_REPORT", "env.csv", "cli.csv", func(c xdperf.Config) any { return c.TCPFlowReport }, "", "env.csv", "cli.csv"},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			// --recv keeps --send=false valid; count also exercises the sender path.
			args := []string{"--device", "lo", "--count", "1k", "--recv"}
			if tc.flag == "count" {
				args = []string{"--device", "lo", "--send=false", "--recv"}
			}
			check := func(want any, extra ...string) {
				t.Helper()
				cfg, err := parseRunArgs(append(args, extra...)...)
				if err != nil {
					t.Fatal(err)
				}
				if got := tc.field(cfg); got != want {
					t.Fatalf("%s = %v, want %v", tc.flag, got, want)
				}
			}
			check(tc.defaultWant)
			t.Setenv(tc.env, tc.envValue)
			check(tc.envWant)
			check(tc.flagWant, "--"+tc.flag+"="+tc.flagValue)
		})
	}
}

func TestParseArgsEnvOnly(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("XDPERF_DEVICE", "env0")
	t.Setenv("XDPERF_DURATION", "500ms")
	t.Setenv("XDPERF_PPS", "10k")
	t.Setenv("XDPERF_RECV", "true")
	cfg, err := parseRunArgs()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Device != "env0" || cfg.Duration != 500*time.Millisecond || cfg.PPS != 10000 || cfg.Count != 5000 || !cfg.Receiver {
		t.Fatalf("unexpected environment config: %+v", cfg)
	}
	cfg, err = parseRunArgs("-d", "cli0", "-t", "1s", "--recv=false")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Device != "cli0" || cfg.Duration != time.Second || cfg.Count != 10000 || cfg.Receiver {
		t.Fatalf("flags did not override environment: %+v", cfg)
	}
}

func TestTCPEnvPluginSelection(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("XDPERF_DEVICE", "lo")
	t.Setenv("XDPERF_TCP", "true")
	t.Setenv("XDPERF_TCP_DST", "192.0.2.1:5201")
	t.Setenv("XDPERF_TCP_BYTES", "1k")
	cfg, err := parseRunArgs()
	if err != nil || cfg.PluginName != "" || !cfg.TCP || cfg.TCPBytes != 1000 {
		t.Fatalf("standalone TCP: config = %+v, err = %v", cfg, err)
	}
	for _, plugin := range []string{"mixed.go", "simpleudp.tinygo"} {
		t.Setenv("XDPERF_PLUGIN", plugin)
		if _, err := parseRunArgs(); err == nil || !strings.Contains(err.Error(), "--tcp cannot be combined with --plugin") {
			t.Fatalf("plugin %q from environment was not treated as explicit: %v", plugin, err)
		}
	}
	if cfg, err := parseRunArgs("--plugin="); err != nil || cfg.PluginName != "" {
		t.Fatalf("empty CLI plugin override: config = %+v, err = %v", cfg, err)
	}
}

func TestParseArgsLoggerEnv(t *testing.T) {
	clearConfigEnv(t)
	cfg, err := parseRunArgs("--device", "lo", "--count", "1k")
	if err != nil || cfg.LoggerConfig != (logger.Config{}) {
		t.Fatalf("logger defaults: %+v, err = %v", cfg.LoggerConfig, err)
	}
	t.Setenv("XDPERF_LOGGERCONFIG_JSON", "true")
	t.Setenv("XDPERF_LOGGERCONFIG_VERBOSE", "2")
	// These field-based names never worked and must not interfere with CLI parsing.
	t.Setenv("XDPERF_PLUGINNAME", "ignored.go")
	t.Setenv("XDPERF_BATCHSIZE", "invalid")
	cfg, err = parseRunArgs("--device", "lo", "--count", "1k")
	if err != nil || !cfg.LoggerConfig.JSON || cfg.LoggerConfig.Verbose != 2 || cfg.PluginName != "simpleudp.tinygo" {
		t.Fatalf("logger environment: config = %+v, err = %v", cfg, err)
	}
}

func TestInvalidEnvValues(t *testing.T) {
	clearConfigEnv(t)
	args := []string{"--device", "lo", "--send=false", "--recv"}
	if _, err := parseRunArgs(args...); err != nil {
		t.Fatalf("baseline must be valid: %v", err)
	}
	for env, wantErr := range map[string]string{
		"XDPERF_BATCH_SIZE":    "batch-size",
		"XDPERF_OTLP_INTERVAL": "otlp-interval",
		"XDPERF_RECV":          "recv",
		"XDPERF_COUNT":         "invalid count value",
		"XDPERF_PPS":           "invalid PPS value",
	} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "invalid")
			if _, err := parseRunArgs(args...); err == nil || !strings.Contains(err.Error(), wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, wantErr)
			}
		})
	}
}

func TestCommandEnvBindings(t *testing.T) {
	for _, command := range newApp("test").Commands {
		for _, flag := range command.Flags {
			name, _, _ := strings.Cut(flag.GetName(), ",")
			want := "XDPERF_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
			got := reflect.ValueOf(flag).FieldByName("EnvVar").String()
			if got != want {
				t.Errorf("%s --%s EnvVar = %q, want %q", command.Name, name, got, want)
			}
		}
	}
}

func TestProbeEnv(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("XDPERF_DEVICE", "env0")
	t.Setenv("XDPERF_JSON", "true")
	app := newApp("test")
	app.Writer, app.ErrWriter = io.Discard, io.Discard
	called := false
	app.Commands[1].Action = func(ctx *cli.Context) error {
		called = true
		if ctx.String("device") != "env0" || !ctx.Bool("json") {
			t.Fatal("probe environment values were not applied")
		}
		return nil
	}
	if err := app.Run([]string{"xdperf", "probe"}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("probe action was not called")
	}
}
