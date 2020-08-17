package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/glog"
	. "github.com/Lafeng/deblocus/tunnel"
	"github.com/urfave/cli/v2"
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
	logdir     string
	debug      bool
	showVer    bool
	vSpecified bool
	vFlag      int
	signals    int32
	config     *ConfigContext
	components []Component
	closeable  []io.Closer
}

// global before handler
func (ctx *bootContext) beforeHandler(c *cli.Context) (err error) {
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

func (ctx *bootContext) initialize(role ServiceRole) (current ServiceRole) {
	var err error
	// load config file
	ctx.config, err = NewConfigContextFromFile(ctx.configFile)
	fatalError(err)

	// parse config file
	current, err = ctx.config.Initialize(role)
	fatalError(err)

	if !ctx.vSpecified { // no -v
		// set logV with config.v
		if v := ctx.config.LogV(current); v > 0 {
			log.SetLogVerbose(v)
		}
	}
	return
}

// ./deblocus csc [-type algo]
func (ctx *bootContext) cscCommandHandler(c *cli.Context) error {
	keyType := c.String("type")
	output := getOutputArg(c)
	err := CreateServerConfigTemplate(output, keyType)
	fatalError(err)
	return nil
}

// ./deblocus ccc [-addr SERV_ADDR:PORT] USER
func (ctx *bootContext) cccCommandHandler(c *cli.Context) error {
	// need server config
	ctx.initialize(SR_SERVER)
	if args := c.Args(); args.Len() == 1 {
		user := args.Get(0)
		pubAddr := c.String("addr")
		output := getOutputArg(c)
		err := ctx.config.CreateClientConfig(output, user, pubAddr)
		fatalError(err)
	} else {
		fatalAndCommandHelp(c)
	}
	return nil
}

func (ctx *bootContext) keyInfoCommandHandler(c *cli.Context) error {
	// need config
	role := ctx.initialize(SR_AUTO)
	fmt.Fprintln(os.Stderr, ctx.config.KeyInfo(role))
	return nil
}

func (ctx *bootContext) startCommandHandler(c *cli.Context) error {
	if c.Args().Len() > 0 {
		fatalAndCommandHelp(c)
	}
	// option as pseudo-command: help, version
	if ctx.showVer {
		fmt.Println(versionString())
		return nil
	}

	var role = ctx.initialize(SR_AUTO)
	switch role {
	case SR_CLIENT:
		go ctx.startClient()

	case SR_SERVER:
		log.Infoln(versionString())
		var server = NewServer(ctx.config)
		for _, trans := range server.Transports() {
			go ctx.startServer(server, trans)
		}
	}

	waitSignal()
	return nil
}

func (ctx *bootContext) startClient() {
	defer ctx.onRoleFinished(SR_CLIENT)

	var (
		conn *net.TCPConn
		ln   *net.TCPListener
		err  error
	)

	config := ctx.config
	client := NewClient(config)
	addr := config.ClientConf().ListenAddr

	ln, err = net.ListenTCP("tcp", addr)
	fatalError(err)
	defer ln.Close()

	ctx.register(client, ln)
	log.Infoln(versionString())
	log.Infoln("Proxy(SOCKS5/HTTP) is listening on", addr)

	// connect to server
	go client.StartTun(true)

	for {
		conn, err = ln.AcceptTCP()
		if err == nil {
			go client.ClientServe(conn)
		} else {
			SafeClose(conn)
		}
	}
}

// start Server base on transport
func (ctx *bootContext) startServer(server *Server, transport *Transport) {
	defer ctx.onRoleFinished(SR_SERVER)

	var (
		conn net.Conn
		ln   net.Listener
		err  error
	)

	ln, err = transport.CreateServerListener(server)
	fatalError(err)
	defer ln.Close()

	log.Infoln("Server is listening on", transport.TransType(), ln.Addr())
	ctx.register(server, ln)

	for {
		conn, err = ln.Accept()
		if err == nil {
			transport.SetupConnection(conn)
			go server.HandleNewConnection(conn)
		} else {
			SafeClose(conn)
		}
	}
}

func (ctx *bootContext) onRoleFinished(role ServiceRole) {
	switch role {
	case SR_CLIENT:
		sigChan <- Bye

	case SR_SERVER:
		if atomic.AddInt32(&ctx.signals, 1) == 2 {
			sigChan <- Bye
		}
	}
}

func (ctx *bootContext) register(cmp Component, cz io.Closer) {
	var exists1, exists2 int
	for _, v := range ctx.components {
		if v == cmp {
			exists1++
		}
	}
	for _, v := range ctx.closeable {
		if v == cz {
			exists2++
		}
	}

	if exists1 == 0 {
		ctx.components = append(ctx.components, cmp)
	}
	if exists2 == 0 {
		ctx.closeable = append(ctx.closeable, cz)
	}
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

/*
func (ctx *bootContext) setLogVerbose(verbose int) {
	// prefer command line v option
	if ctx.vFlag >= 0 {
		log.SetLogVerbose(ctx.vFlag)
	} else {
		log.SetLogVerbose(verbose)
	}
}
*/

func getOutputArg(c *cli.Context) string {
	output := c.String("output")
	if output != NULL && !strings.Contains(output, ".") {
		output += ".ini"
	}
	return output
}

func waitSignal() {
	USR2 := syscall.Signal(12) // fake signal-USR2 for windows
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, USR2)
	for sig := range sigChan {
		switch sig {
		case Bye:
			log.Exitln("Exiting.")
			context.doClose()
			return
		case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			log.Exitln("Terminated by", sig)
			context.doClose()
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
	fmt.Println("Unknown input --->", strings.Join(c.Args().Slice(), " "))
	context.doClose()
	cli.ShowAppHelpAndExit(c, 2)
}
