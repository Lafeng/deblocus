package main

import (
	"os"

	"github.com/urfave/cli/v2"
)

func setupCommands() *cli.App {
	app := cli.NewApp()
	app.Name = app_name
	app.Usage = project_url
	app.Version = versionString() + "\n   " + buildInfo()
	app.HideVersion = true
	//app.HideHelp = true
	globalOptions := []cli.Flag{
		&cli.StringFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Usage:       "indicate Config path if it in nontypical path",
			Destination: &context.configFile,
		},
		&cli.IntFlag{
			Name:        "v",
			Usage:       "Verbose log level",
			Destination: &context.vFlag,
		},
		&cli.StringFlag{
			Name:        "logdir",
			Aliases:     []string{"ld"},
			Usage:       "write log into the directory",
			Destination: &context.logdir,
		},
		&cli.BoolFlag{
			Name:        "version",
			Aliases:     []string{"V"},
			Usage:       "show version",
			Destination: &context.showVer,
		},
		&cli.BoolFlag{
			Name:        "debug",
			Usage:       "debug",
			Destination: &context.debug,
		},
	}
	subOptions := []cli.Flag{
		&cli.StringFlag{
			Name:    "type",
			Aliases: []string{"t"},
			Usage:   "Specify type of key to create.",
		},
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"o"},
			Usage:   "Output file",
		},
		&cli.StringFlag{
			Name:    "addr",
			Aliases: []string{"a"},
			Usage:   "Public Address",
		},
	}
	app.Commands = []*cli.Command{
		{
			Name:        "csc",
			Usage:       "Create server config template",
			ArgsUsage:   "deblocus csc [options]",
			Description: _csc_examples,
			Action:      context.cscCommandHandler,
			Flags:       subOptions[:2],
		},
		{
			Name:        "ccc",
			Usage:       "Create client config of specified user",
			ArgsUsage:   "deblocus ccc [options] <username>",
			Description: _ccc_examples,
			Action:      context.cccCommandHandler,
			Flags:       append(subOptions[1:], globalOptions[0]),
		},
		{
			Name:        "keyinfo",
			Usage:       "Print key info from config",
			ArgsUsage:   "deblocus keyinfo [options]",
			Description: _keyinfo_examples,
			Action:      context.keyInfoCommandHandler,
			Flags:       []cli.Flag{globalOptions[0]},
		},
	}
	app.Flags = globalOptions
	app.Before = context.beforeHandler
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
   ./deblocus csc -o deblocus.ini
   ./deblocus csc -t [ECC-P224,256,384,521 | RSA-1024,2048,4096]`

const _ccc_examples = `
   ./deblocus ccc --addr=example.com:9008  user
   ./deblocus ccc -o file user`

const _keyinfo_examples = `
   ./deblocus keyinfo
   ./deblocus keyinfo -c someconfig.ini`
