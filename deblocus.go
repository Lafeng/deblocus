package main

import (
	"os"

	"github.com/codegangsta/cli"
)

func setupCommands() *cli.App {
	app := cli.NewApp()
	app.Name = app_name
	app.Usage = project_url
	app.Version = versionString() + "\n   " + buildInfo()
	app.HideVersion = true
	//app.HideHelp = true
	flags := []cli.Flag{
		cli.StringFlag{
			Name:        "o",
			Usage:       "output file",
			Destination: &context.output,
		},
		cli.StringFlag{
			Name:        "config, c",
			Usage:       "indicate Config path if it in nontypical path",
			Destination: &context.configFile,
		},
		cli.IntFlag{
			Name:        "v",
			Usage:       "Verbose log level",
			Destination: &context.vFlag,
		},
		cli.StringFlag{
			Name:        "logdir, l",
			Usage:       "write log into the directory",
			Destination: &context.logdir,
		},
		cli.BoolFlag{
			Name:        "version, V",
			Usage:       "show version",
			Destination: &context.showVer,
		},
		cli.BoolFlag{
			Name:        "debug",
			Usage:       "debug",
			Destination: &context.debug,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:   "csc",
			Usage:  "Create Server Config",
			Action: context.cscCommandHandler,
		},
		{
			Name:        "ccc",
			Usage:       "Create Client Config",
			Description: "Description",
			Action:      context.cccCommandHandler,
			Flags:       flags[:2],
		},
	}
	app.Flags = flags[1:]
	app.Before = context.initialize
	app.Action = context.startCommandHandler
	return app
}

func main() {
	app := setupCommands()
	app.Run(os.Args)
}
