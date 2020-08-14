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
	kcp "github.com/xtaci/kcp-go/v5"
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

func (ctx *bootContext) initConfig(r ServerRole) (role ServerRole) {
	var err error
	// load config file
	ctx.cman, err = DetectConfig(ctx.configFile)
	fatalError(err)
	// parse config file
	role, err = ctx.cman.InitConfigByRole(r)
	if role == 0 {
		err = fmt.Errorf("No server role defined in config")
	}
	fatalError(err)
	if !ctx.vSpecified { // no -v
		// set logV with config.v
		if v := ctx.cman.LogV(role); v > 0 {
			log.SetLogVerbose(v)
		}
	}
	return role
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
	ctx.initConfig(SR_SERVER)
	if args := c.Args(); args.Len() == 1 {
		user := args.Get(0)
		pubAddr := c.String("addr")
		output := getOutputArg(c)
		err := ctx.cman.CreateClientConfig(output, user, pubAddr)
		fatalError(err)
	} else {
		fatalAndCommandHelp(c)
	}
	return nil
}

func (ctx *bootContext) keyInfoCommandHandler(c *cli.Context) error {
	// need config
	role := ctx.initConfig(SR_AUTO)
	fmt.Fprintln(os.Stderr, ctx.cman.KeyInfo(role))
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

	role := ctx.initConfig(SR_AUTO)
	if role&SR_SERVER != 0 {
		log.Infoln(versionString())
		go ctx.startServer1()
		go ctx.startServer2()
	}

	if role&SR_CLIENT != 0 {
		go ctx.startClient()
	}

	waitSignal()
	return nil
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

// start TCP Server
func (ctx *bootContext) startServer1() {
	defer ctx.serverOffline()
	var (
		conn *net.TCPConn
		ln   *net.TCPListener
		err  error
	)

	server := NewServer(ctx.cman)
	ln, err = net.ListenTCP("tcp", server.ListenAddr)
	fatalError(err)
	defer ln.Close()

	ctx.register(server, ln)
	log.Infoln("Server is listening on", ln.Addr())

	for {
		conn, err = ln.AcceptTCP()
		if err == nil {
			go server.TunnelServe(conn)
		} else {
			SafeClose(conn)
		}
	}
}

// start UDP Server
func (ctx *bootContext) startServer2() {
	defer ctx.serverOffline()
	var (
		conn *kcp.UDPSession
		ln   *kcp.Listener
		err  error
	)

	server := NewServer(ctx.cman)
	ln, err = kcp.ListenWithOptions(server.Listen, nil, KCP_FEC_DATASHARD, KCP_FEC_PARITYSHARD)
	fatalError(err)
	defer ln.Close()

	ctx.register(server, ln)
	log.Infoln("Server is listening on", ln.Addr())

	for {
		conn, err = ln.AcceptKCP()
		if err == nil {
			go server.TunnelServe(conn)
		} else {
			SafeClose(conn)
		}
	}
}

func (ctx *bootContext) serverOffline() {
	if atomic.AddInt32(&ctx.signals, 1) == 2 {
		sigChan <- Bye
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
