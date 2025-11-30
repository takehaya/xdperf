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
		cli.BoolFlag{
			Name:  "server, s",
			Usage: "run as server mode",
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
		cli.IntFlag{
			Name:  "count, c",
			Value: 1,
			Usage: "number of packets to send",
		},
		cli.IntFlag{
			Name:  "debugmode, D",
			Value: 0,
			Usage: "debug mode level (0: none, 1: on, 2: full verbose)",
		},
		cli.BoolFlag{
			Name:  "server-swap-resp, swap",
			Usage: "server mode: swap response packets (for echo server)",
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
	c.ServerFlag = ctx.Bool("server")
	c.Device = ctx.String("device")
	c.Parallelism = ctx.Int("parallelism")
	c.Count = ctx.Int("count")
	c.DebugMode = ctx.Int("debugmode")
	c.PluginLanguage = ctx.String("plugin-language")
	c.ServerSwapResp = ctx.Bool("server-swap-resp")

	if c.DebugMode > 0 {
		// set verbose logging
		c.LoggerConfig.Verbose = 1
	}

	// Validate config
	if err := c.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
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

	if c.ServerFlag {
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
