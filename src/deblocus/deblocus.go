package main

import (
	ex "deblocus/exception"
	t "deblocus/tunnel"
	"flag"
	"fmt"
	log "golang/glog"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var context = &bootContext{}
var sigChan = make(chan os.Signal)

func waitSignal() {
	USR2 := syscall.Signal(12) // fuck windows without many signals
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, USR2)
	for sig := range sigChan {
		switch sig {
		case t.Bye:
			return
		case syscall.SIGINT, syscall.SIGTERM:
			log.Infoln("Terminated by signal", sig)
			return
		case USR2:
			context.doStats()
		default:
			log.Infoln("Ingore signal", sig)
		}
	}
}

func main() {
	var output string
	var showVersion bool
	flag.Usage = showUsage
	flag.StringVar(&context.listen, "l", "", "listen on [HOST]:PORT")
	flag.StringVar(&context.config, "config", "", "Server;;indicate config if in nontypical path")
	flag.StringVar(&output, "o", "", "output file")
	flag.BoolVar(&context.csc, "csc", false, "Server;;Create Server Config")
	flag.BoolVar(&context.icc, "icc", false, "Server;;Issue Client Credential for user")
	flag.BoolVar(&context.isServ, "serv", false, "Server;;Run as server explicitly or InitCap")
	flag.BoolVar(&showVersion, "ver", false, "show version")
	flag.StringVar(&context.verbosity, "v", "", "verbose log level")
	flag.Parse()

	context.parse()
	log.Set_toStderr(true)

	if showVersion {
		println(versionString())
		return
	}

	if context.csc {
		t.Generate_d5sFile(output, nil)
		return
	}

	if context.icc {
		if flag.NArg() > 0 {
			var d5sc = t.Parse_d5sFile(context.config)
			for _, arg := range flag.Args() {
				t.CreateClientCredential(d5sc, arg)
			}
			return
		} else {
			fmt.Println("Which user do you issue client credential for?")
			os.Exit(2)
		}
	}

	if context.isServ {
		go startServer(context)
	} else {
		go startClient(context)
	}
	waitSignal()
}

func startClient(context *bootContext) {
	defer func() {
		ex.CatchException(recover())
		sigChan <- t.Bye
	}()
	d5c := t.Parse_d5cFile(context.config)
	setLogVerbose(context, d5c.Verbose)
	mgr := NewClientMgr(d5c)
	context.statser = mgr
	lAddr := d5c.Listen
	if len(context.listen) > 0 {
		lAddr = context.listen
	}
	ln, err := net.Listen("tcp", lAddr)
	t.ThrowErr(err)
	defer ln.Close()
	log.Infoln("deblocus client/starting", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err == nil {
			go mgr.selectClientServ(conn)
		}
	}
}

func startServer(context *bootContext) {
	defer func() {
		ex.CatchException(recover())
		sigChan <- t.Bye
	}()
	var conf = t.Parse_d5sFile(context.config)
	setLogVerbose(context, conf.Verbose)
	var lAddr = conf.ListenAddr
	if len(context.listen) > 0 {
		var err error
		lAddr, err = net.ResolveTCPAddr("tcp", context.listen)
		t.ThrowErr(err)
	}
	ln, err := net.ListenTCP("tcp", lAddr)
	t.ThrowErr(err)
	defer ln.Close()
	log.Infoln("deblocus server/starting", ln.Addr())
	dhKeys := t.GenerateDHKeyPairs()
	server := t.NewServer(conf, dhKeys)
	context.statser = server
	for {
		conn, err := ln.AcceptTCP()
		if err == nil {
			go server.TunnelServe(conn)
		}
	}
}

func setLogVerbose(context *bootContext, level int) {
	var vFlag = context.verbosity
	var v int = -1
	if len(vFlag) > 0 {
		if len(vFlag) == 1 && vFlag[0] >= 48 && vFlag[0] <= 57 {
			v = int(vFlag[0]) - 48
		} else {
			fmt.Println("Warning: invalid option -v=" + vFlag)
		}
	}
	if v >= 0 {
		log.Set_Verbose(v)
	} else {
		log.Set_Verbose(level)
	}
}
