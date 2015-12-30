package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/golang/glog"
	. "github.com/Lafeng/deblocus/tunnel"
	"github.com/codegangsta/cli"
)

var (
	context = &bootContext{}
	sigChan = make(chan os.Signal)
)

type Component interface {
	Stats() string
	Close()
}

type bootContext struct {
	configFile string
	output     string
	logdir     string
	debug      bool
	showVer    bool
	vSpecified bool
	vFlag      int
	cman       *ConfigMan
	components []Component
	closeable  []io.Closer
}

// global before handler
func (ctx *bootContext) initialize(c *cli.Context) (err error) {
	// inject parameters into package.tunnel
	VER_STRING = versionString()
	VERSION = version
	DEBUG = ctx.debug
	// inject parameters into package.exception
	ex.DEBUG = ctx.debug
	// glog
	ctx.vSpecified = c.IsSet("v")
	log.SetLogOutput(ctx.logdir)
	log.SetLogVerbose(ctx.vFlag)
	return nil
}

func (ctx *bootContext) initConfig(r ServerRole) ServerRole {
	var serverRole ServerRole
	var err error
	// load config file
	ctx.cman, err = DetectConfig(ctx.configFile)
	fatalError(err)
	// parse config file
	serverRole, err = ctx.cman.InitConfigByRole(r)
	fatalError(err)
	// reset logV
	if !ctx.vSpecified {
		if v := ctx.cman.LogV(r); v > 0 {
			log.SetLogVerbose(v)
		}
	}
	return serverRole
}

// ./deblocus -csc [algo]
func (ctx *bootContext) cscCommandHandler(c *cli.Context) {
	var keyOpt string

	switch args := c.Args(); len(args) {
	case 0:
	case 1:
		keyOpt = args.Get(0)
	default:
		fatalAndCommandHelp(c)
	}

	err := CreateServerConfigTemplate(ctx.output, keyOpt)
	fatalError(err)
}

// ./deblocus -ccc SERV_ADDR:PORT USER
func (ctx *bootContext) cccCommandHandler(c *cli.Context) {
	// need server config
	ctx.initConfig(SR_SERVER)

	if args := c.Args(); len(args) == 2 {
		addr, user := args.Get(0), args.Get(1)
		// validate arg0:ListenAddr
		_, err := IsValidHost(addr)
		fatalError(err)

		err = ctx.cman.CreateClientConfig(ctx.output, user, addr)
		fatalError(err)
	} else {
		fatalAndCommandHelp(c)
	}
}

func (ctx *bootContext) startCommandHandler(c *cli.Context) {
	if len(c.Args()) > 0 {
		fatalAndCommandHelp(c)
	}
	// option as pseudo-command: help, version
	if ctx.showVer {
		fmt.Fprintln(os.Stderr, versionString())
		return
	}

	role := ctx.initConfig(SR_AUTO)
	if role&SR_SERVER != 0 {
		go ctx.startServer()
	}
	if role&SR_CLIENT != 0 {
		go ctx.startClient()
	}
	waitSignal()
}

func (ctx *bootContext) startClient() {
	defer func() {
		sigChan <- Bye
	}()
	var (
		conn *net.TCPConn
		ln   *net.TCPListener
		err  error
	)

	client := NewClient(ctx.cman)
	addr := ctx.cman.ListenAddr(SR_CLIENT)

	ln, err = net.ListenTCP("tcp", addr)
	fatalError(err)
	defer ln.Close()

	ctx.register(client, ln)
	log.Infoln(versionString())
	log.Infoln("Proxy(SOCKS5/HTTP) is working at", addr)

	// connect to server
	go client.StartTun(true)

	for {
		conn, err = ln.AcceptTCP()
		if err == nil {
			if client.IsReady() {
				go client.ClientServe(conn)
				continue
			} else {
				log.Errorf("No available tunnels for servicing new request")
				time.Sleep(time.Second)
			}
		}
		SafeClose(conn)
	}
}

func (ctx *bootContext) startServer() {
	defer func() {
		sigChan <- Bye
	}()
	var (
		conn *net.TCPConn
		ln   *net.TCPListener
		err  error
	)

	server := NewServer(ctx.cman)
	addr := ctx.cman.ListenAddr(SR_SERVER)

	ln, err = net.ListenTCP("tcp", addr)
	fatalError(err)
	defer ln.Close()

	ctx.register(server, ln)
	log.Infoln(versionString())
	log.Infoln("Server is listening on", addr)

	for {
		conn, err = ln.AcceptTCP()
		if err == nil {
			go server.TunnelServe(conn)
		} else {
			SafeClose(conn)
		}
	}
}

func (ctx *bootContext) register(cmp Component, cz io.Closer) {
	ctx.components = append(ctx.components, cmp)
	ctx.closeable = append(ctx.closeable, cz)
}

func (ctx *bootContext) doStats() {
	if ctx.components != nil {
		for _, t := range ctx.components {
			fmt.Fprintln(os.Stderr, t.Stats())
		}
	}
}

func (ctx *bootContext) doClose() {
	for _, t := range ctx.closeable {
		t.Close()
	}
	for _, t := range ctx.components {
		t.Close()
	}
}

func (ctx *bootContext) setLogVerbose(verbose int) {
	// prefer command line v option
	if ctx.vFlag >= 0 {
		log.SetLogVerbose(ctx.vFlag)
	} else {
		log.SetLogVerbose(verbose)
	}
}

func waitSignal() {
	USR2 := syscall.Signal(12) // fake signal-USR2 for windows
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, USR2)
	for sig := range sigChan {
		switch sig {
		case Bye:
			context.doClose()
			log.Exitln("Exiting.")
			return
		case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			context.doClose()
			log.Exitln("Terminated by", sig)
			return
		case USR2:
			context.doStats()
		default:
			log.Infoln("Ingore signal", sig)
		}
	}
}

func fatalError(err error, args ...interface{}) {
	if err != nil {
		msg := err.Error()
		if len(args) > 0 {
			msg += fmt.Sprint(args...)
		}
		fmt.Fprintln(os.Stderr, msg)
		context.doClose()
		os.Exit(1)
	}
}

func fatalAndCommandHelp(c *cli.Context) {
	// app root
	if c.Parent() == nil {
		cli.HelpPrinter(os.Stderr, cli.AppHelpTemplate, c.App)
	} else { // command
		cli.HelpPrinter(os.Stderr, cli.CommandHelpTemplate, c.Command)
	}
	context.doClose()
	os.Exit(1)
}

func advice(e interface{}) interface{} {
	if err, y := e.(error); y {
		var incompatible bool
		// 0.10 altered config field names
		incompatible = incompatible || strings.HasPrefix(err.Error(), UNRECOGNIZED_SYMBOLS.Error())
		// 0.12 altered cipher
		incompatible = incompatible || strings.HasPrefix(err.Error(), UNSUPPORTED_CIPHER.Error())

		if incompatible {
			fmt.Fprintf(os.Stderr, " * Maybe there is an issue of some incompatible alterations caused.\n")
			fmt.Fprintf(os.Stderr, " * Please read %s/wiki to learn more.\n", project_url)
		}
	}
	return e
}
