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
			Name:        "csc",
			Usage:       "Create server config template",
			ArgsUsage:   "deblocus csc [-o file]",
			Description: _csc_examples,
			Action:      context.cscCommandHandler,
			Flags:       flags[:1],
		},
		{
			Name:        "ccc",
			Usage:       "Create client config of specified user",
			ArgsUsage:   "deblocus ccc [options] <server_addr:port> <username>",
			Description: _ccc_examples,
			Action:      context.cccCommandHandler,
			Flags:       flags[:2],
		},
	}
	app.Flags = flags[1:]
	app.Before = context.initialize
	app.Action = context.startCommandHandler
	cli.CommandHelpTemplate = CommandHelpTemplate
	return app
}

func main() {
	app := setupCommands()
	app.Run(os.Args)
}

// In fact, cli.Usage is description
// regard cli.ArgsUsage as usage
// regard cli.Description as examples
const CommandHelpTemplate = `COMMAND:
   {{.HelpName}} - {{.Usage}}{{if .ArgsUsage}}

USAGE:
   {{.ArgsUsage}}{{end}}{{if .Description}}

EXAMPLES:{{.Description}}{{end}}{{if .Flags}}

OPTIONS:
   {{range .Flags}}{{.}}
   {{end}}{{end}}
`

const _csc_examples = `
   ./deblocus csc > deblocus.ini
   ./deblocus csc -o deblocus.ini`

const _ccc_examples = `
   ./deblocus ccc example.com:9008 user
   ./deblocus ccc example.com:9008 user -o file`
