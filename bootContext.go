package main

import (
	"flag"
	"fmt"
	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/golang/glog"
	t "github.com/Lafeng/deblocus/tunnel"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	DH_METHOD = "ECDHE-P256"
)

type Component interface {
	Stats() string
	Close()
}

type bootContext struct {
	config     string
	isServ     bool
	csc        bool
	ccc        bool
	verbosity  string
	debug      bool
	components []Component
}

func (c *bootContext) parse() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	if !c.isServ {
		c.isServ = c.ccc || t.DetectRunAsServ()
	}
	if c.config == "" && !c.csc {
		var e bool
		c.config, e = t.DetectFile(c.isServ)
		if !e {
			fmt.Fprintln(os.Stderr, "No such file", c.config)
			fmt.Fprintln(os.Stderr, "Create/put config in typical path or indicate it explicitly.")
			os.Exit(1)
		}
	}
	// inject parameters into sub-packages
	t.VERSION = version
	t.VER_STRING = versionString()
	t.DEBUG = c.debug
	ex.DEBUG = c.debug
}

func (c *bootContext) doStats() {
	if c.components != nil {
		for _, t := range c.components {
			fmt.Fprintln(os.Stderr, t.Stats())
		}
	}
}

func (c *bootContext) doClose() {
	if c.components != nil {
		for _, t := range c.components {
			t.Close()
		}
	}
}

func (c *bootContext) setLogVerbose(level int) {
	var vFlag = c.verbosity
	var v int = -1
	if len(vFlag) > 0 {
		if len(vFlag) == 1 && vFlag[0] >= 48 && vFlag[0] <= 57 {
			v = int(vFlag[0]) - 48
		} else {
			fmt.Fprintln(os.Stderr, "Warning: invalid option -v="+vFlag)
		}
	}
	if v >= 0 {
		log.SetLogVerbose(v)
	} else {
		log.SetLogVerbose(level)
	}
}

func (c *bootContext) cscHandler(output string) {
	// ./deblocus -csc [1024 or 2048]
	var rsaParam string
	switch flag.NArg() {
	case 0:
	case 1:
		rsaParam = flag.Arg(0)
	default:
		fmt.Fprintln(os.Stderr, "Incorrect arguments")
		return
	}
	if e := t.GenerateD5sTemplate(output, rsaParam); e != nil {
		fmt.Fprintln(os.Stderr, e)
	}
}

func (c *bootContext) cccHandler(output string) {
	// ./deblocus -ccc SERV_ADDR:PORT USER
	if flag.NArg() == 2 {
		addr := flag.Arg(0)
		if v, e := t.IsValidHost(addr); !v {
			fmt.Fprintln(os.Stderr, e)
			return
		}
		var d5sc = t.Parse_d5s_file(c.config)
		d5sc.Listen = addr
		if e := t.CreateClientConfig(output, d5sc, flag.Arg(1)); e != nil {
			fmt.Fprintln(os.Stderr, e)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Incorrect arguments")
	}
}

func (context *bootContext) startClient() {
	defer func() {
		ex.CatchException(warning(recover()))
		sigChan <- t.Bye
	}()
	var conf = t.Parse_d5c_file(context.config)
	context.setLogVerbose(conf.Verbose)
	log.Infoln(versionString())
	log.Infoln("Socks5/Http is working at", conf.ListenAddr)

	ln, err := net.ListenTCP("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()
	dhKey, _ := t.NewDHKey(DH_METHOD)
	client := t.NewClient(conf, dhKey)
	context.components = append(context.components, client)
	go client.StartTun(true)

	for {
		conn, err := ln.Accept()
		if err == nil {
			if client.IsReady() {
				go client.ClientServe(conn)
				continue
			} else {
				log.Errorf("No available tunnels for servicing new request")
				time.Sleep(time.Second)
			}
		}
		t.SafeClose(conn)
	}
}

func (context *bootContext) startServer() {
	defer func() {
		ex.CatchException(warning(recover()))
		sigChan <- t.Bye
	}()
	var conf = t.Parse_d5s_file(context.config)
	context.setLogVerbose(conf.Verbose)
	log.Infoln(versionString())
	log.Infoln("Server is listening on", conf.ListenAddr)

	ln, err := net.ListenTCP("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	dhKey, _ := t.NewDHKey(DH_METHOD)
	server := t.NewServer(conf, dhKey)
	context.components = append(context.components, server)
	for {
		conn, err := ln.AcceptTCP()
		if err == nil {
			go server.TunnelServe(conn)
		} else {
			t.SafeClose(conn)
		}
	}
}

func warning(e interface{}) interface{} {
	if err, y := e.(error); y {
		// 0.9.x to 0.10.x config error
		if strings.HasPrefix(err.Error(), "Unrecognized directives") {
			log.Warningf("Please read %s/wiki to learn more.", project_url)
		}
	}
	return e
}
