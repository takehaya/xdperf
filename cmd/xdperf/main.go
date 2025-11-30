package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/kelseyhightower/envconfig"
	"github.com/takehaya/xdperf/pkg/xdperf"
	"github.com/urfave/cli"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	app := newApp(version)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "Xdperf"
	app.Version = fmt.Sprintf("%s, %s, %s, %s", version, commit, date, builtBy)

	app.Usage = "high performance XDP based network traffic generator tool"

	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "plugin, p",
			Value: "simpleudp.tinygo",
			Usage: "wasm pkt gen plugin file name",
		},
		cli.StringFlag{
			Name:  "plugin-language, L",
			Usage: "wasm plugin language (go or tinygo etc...)",
		},
		cli.StringFlag{
			Name:  "plugin-path, P",
			Value: "/usr/local/share/xdperf/plugins",
			Usage: "plugin path, default is /usr/local/share/xdperf/plugins",
		},
		cli.StringFlag{
			Name:  "plugin-config, cfg",
			Usage: "plugin configuration (JSON format)",
		},
		cli.StringFlag{
			Name:  "plugin-config-path, cfgpath",
			Usage: "plugin configuration file path (JSON format)",
		},
		cli.BoolTFlag{
			Name:  "send, s",
			Usage: "run as send mode",
		},
		cli.BoolFlag{
			Name:  "recv, r",
			Usage: "run as receive mode",
		},
		cli.BoolFlag{
			Name:  "swap-resp, swap",
			Usage: "swap response packets (for echo server)",
		},
		cli.StringFlag{
			Name:     "device, d",
			Required: true,
			Usage:    "network device name to send packets",
		},
		cli.IntFlag{
			Name:  "parallelism, l",
			Value: 1,
			Usage: "number of parallel packet sending threads",
		},
		cli.StringFlag{
			Name:  "count, c",
			Usage: "number of packets to send (e.g., 100k, 1m). Required if --duration not specified",
		},
		cli.DurationFlag{
			Name:  "duration, t",
			Usage: "duration to send packets (e.g., 10s, 1m). Required if --count not specified",
		},
		cli.IntFlag{
			Name:  "debugmode, D",
			Value: 0,
			Usage: "debug mode level (0: none, 1: on, 2: full verbose)",
		},
		cli.StringFlag{
			Name:  "pps",
			Value: "",
			Usage: "target packets per second (e.g., 100k, 1m). Empty for max speed",
		},
		cli.BoolFlag{
			Name:  "show-nic-stats",
			Usage: "show NIC-level statistics (may include other traffic on the same interface)",
		},
	}
	app.Action = run
	return app
}

func run(ctx *cli.Context) error {
	var c xdperf.Config
	err := envconfig.Process("manager", &c)
	if err != nil {
		return fmt.Errorf("config parsing failed: %w", err)
	}
	c.PluginName = ctx.String("plugin")
	c.PluginPath = ctx.String("plugin-path")
	c.PluginConfig = ctx.String("plugin-config")
	c.PluginConfigPath = ctx.String("plugin-config-path")
	c.Sender = ctx.Bool("send")
	c.Receiver = ctx.Bool("recv")
	c.Device = ctx.String("device")
	c.Parallelism = ctx.Int("parallelism")
	c.Duration = ctx.Duration("duration")
	c.DebugMode = ctx.Int("debugmode")
	c.PluginLanguage = ctx.String("plugin-language")
	c.SwapResp = ctx.Bool("swap-resp")
	c.ShowNICStats = ctx.Bool("show-nic-stats")

	// Parse count
	countStr := ctx.String("count")
	count, err := xdperf.ParseCount(countStr)
	if err != nil {
		return fmt.Errorf("invalid count value: %w", err)
	}
	c.Count = count

	// Parse PPS
	ppsStr := ctx.String("pps")
	pps, err := xdperf.ParsePPS(ppsStr)
	if err != nil {
		return fmt.Errorf("invalid PPS value: %w", err)
	}
	c.PPS = pps

	if c.DebugMode > 0 {
		// set verbose logging
		c.LoggerConfig.Verbose = 1
	}

	// Validate config
	if err := c.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Calculate count from duration if specified (after validation)
	// Use float64 to support sub-second durations (e.g., 0.5s, 500ms)
	if c.Duration > 0 && c.PPS > 0 {
		c.Count = uint64(float64(c.PPS) * c.Duration.Seconds())
	}

	// Post-validation: check count >= parallelism after duration calculation
	if c.Count > 0 && c.Count < uint64(c.Parallelism) {
		return fmt.Errorf("calculated count (%d) must be greater than or equal to parallelism (%d)", c.Count, c.Parallelism)
	}

	// plugin config load
	if c.PluginConfig == "" && c.PluginConfigPath != "" {
		configData, err := os.ReadFile(c.PluginConfigPath)
		if err != nil {
			return fmt.Errorf("failed to read plugin config file: %w", err)
		}
		c.PluginConfig = string(configData)
	}

	xdp, err := xdperf.NewXdperf(c)
	if err != nil {
		return fmt.Errorf("xdperf initialization failed: %w", err)
	}
	defer xdp.Close()

	if c.Receiver && !c.Sender {
		err = xdp.StartServer(context.Background())
		if err != nil {
			return fmt.Errorf("xdperf server start failed: %w", err)
		}
		return nil
	}

	err = xdp.StartClient(context.Background())
	if err != nil {
		return fmt.Errorf("xdperf client start failed: %w", err)
	}
	return nil
}
