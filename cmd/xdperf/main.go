package main

import (
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
			Value: "simple",
			Usage: "plugin file name",
		},
		cli.StringFlag{
			Name:  "plugin-path, P",
			Value: "/usr/local/lib/xdperf/plugins/",
			Usage: "plugin path, default is /usr/local/lib/xdperf/plugins/",
		},
		cli.BoolFlag{
			Name:  "server, s",
			Usage: "run as server mode",
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
	c.ServerFlag = ctx.Bool("server")

	xdperf, err := xdperf.NewXdperf(c)
	if err != nil {
		return fmt.Errorf("xdperf initialization failed: %w", err)
	}
	defer xdperf.Close()
	return nil
}
