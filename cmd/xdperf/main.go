package main

import (
	"fmt"
	"log"
	"os"

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

	app.Usage = ""

	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "plugin, p",
			Value: "simple",
			Usage: "plugin file name",
		},
		cli.StringFlag{
			Name:  "plugin-path, P",
			Usage: "plugin path, default is /usr/local/lib/xdperf/plugins/",
		},
	}
	app.Action = run
	return app
}

func run(ctx *cli.Context) error {
	return nil
}
