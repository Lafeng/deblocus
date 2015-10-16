package main

import (
	"flag"
	"fmt"
	c "github.com/Lafeng/deblocus/crypto"
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
	vFlag      int
	debug      bool
	components []Component
}

func (c *bootContext) parse() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	if !c.isServ {
		c.isServ = c.ccc || t.DetectRunAsServ()
	}
	if c.config == "" && !c.csc {
		var ok bool
		c.config, ok = t.DetectFile(c.isServ)
		fatalIf(!ok, "No such file "+c.config+
			"\nCreate/put config in typical path or indicate it explicitly.")
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

func (c *bootContext) setLogVerbose(verbose int) {
	if c.vFlag >= 0 {
		log.SetLogVerbose(c.vFlag)
	} else {
		log.SetLogVerbose(verbose)
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
		fatal("Incorrect arguments")
	}
	err := t.GenerateD5sTemplate(output, rsaParam)
	fatalIf(err != nil, err)
}

func (c *bootContext) cccHandler(output string) {
	// ./deblocus -ccc SERV_ADDR:PORT USER
	if flag.NArg() == 2 {
		addr := flag.Arg(0)
		v, err := t.IsValidHost(addr)
		fatalIf(!v, err)

		d5sc, err := t.Parse_d5s_file(c.config)
		fatalIf(err != nil, advice(err))

		d5sc.Listen = addr
		err = t.CreateClientConfig(output, d5sc, flag.Arg(1))
		fatalIf(err != nil, err)
	} else {
		fatal("Incorrect arguments")
	}
}

func (context *bootContext) startClient() {
	defer func() {
		ex.CatchException(advice(recover()))
		sigChan <- t.Bye
	}()
	conf, err := t.Parse_d5c_file(context.config)
	if err != nil {
		log.Fatalln(advice(err))
	}

	context.setLogVerbose(conf.Verbose)
	log.Infoln(versionString())
	log.Infoln("Socks5/Http is working at", conf.ListenAddr)

	ln, err := net.ListenTCP("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	dhKey, _ := c.NewDHKey(DH_METHOD)
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
		ex.CatchException(advice(recover()))
		sigChan <- t.Bye
	}()
	conf, err := t.Parse_d5s_file(context.config)
	if err != nil {
		log.Fatalln(advice(err))
	}

	context.setLogVerbose(conf.Verbose)
	log.Infoln(versionString())
	log.Infoln("Server is listening on", conf.ListenAddr)

	ln, err := net.ListenTCP("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	dhKey, _ := c.NewDHKey(DH_METHOD)
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

func fatalIf(cond bool, args ...interface{}) {
	if cond {
		fatal(args...)
	}
}

func fatalf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, msg)
	os.Exit(1)
}

func fatal(args ...interface{}) {
	msg := fmt.Sprint(args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, msg)
	os.Exit(1)
}

func advice(e interface{}) interface{} {
	if err, y := e.(error); y {
		var incompatible bool
		// 0.10 altered config field names
		incompatible = incompatible || strings.HasPrefix(err.Error(), t.UNRECOGNIZED_DIRECTIVES.Error())
		// 0.12 altered cipher
		incompatible = incompatible || strings.HasPrefix(err.Error(), t.UNSUPPORTED_CIPHER.Error())

		if incompatible {
			fmt.Fprintf(os.Stderr, " * Maybe there is an issue of some incompatible alterations caused.\n")
			fmt.Fprintf(os.Stderr, " * Please read %s/wiki to learn more.\n", project_url)
		}
	}
	return e
}
