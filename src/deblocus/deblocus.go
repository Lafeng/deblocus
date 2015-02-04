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
	USR2 := syscall.Signal(12) // fake signal-USR2 for windows
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, USR2)
	for sig := range sigChan {
		switch sig {
		case t.Bye:
			log.Exitln("Exiting.")
			return
		case syscall.SIGINT, syscall.SIGTERM:
			log.Exitln("Terminated by signal", sig)
			return
		case USR2:
			context.doStats()
		default:
			log.Infoln("Ingore signal", sig)
		}
	}
}

func main() {
	var output, logDir string
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
	flag.StringVar(&logDir, "logdir", "", "If non-empty, write log files in this directory")
	flag.Parse()
	context.parse()
	log.Set_output(true, logDir)

	if showVersion {
		fmt.Println(versionString())
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
	var conf = t.Parse_d5cFile(context.config)
	context.setLogVerbose(conf.Verbose)
	log.Info(versionString())
	log.Infoln("Client is starting at", conf.ListenAddr)

	mgr := NewClientMgr(conf)
	context.statser = mgr // for do stats

	ln, err := net.ListenTCP("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err == nil {
			go mgr.selectClientServ(conn)
		} else {
			t.SafeClose(conn)
		}
	}
}

func startServer(context *bootContext) {
	defer func() {
		ex.CatchException(recover())
		sigChan <- t.Bye
	}()
	var conf = t.Parse_d5sFile(context.config)
	context.setLogVerbose(conf.Verbose)
	log.Info(versionString())
	log.Infoln("Server is starting at", conf.ListenAddr)

	ln, err := net.ListenTCP("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	dhKeys := t.GenerateDHKeyPairs()
	server := t.NewServer(conf, dhKeys)
	context.statser = server
	for {
		conn, err := ln.AcceptTCP()
		if err == nil {
			go server.TunnelServe(conn)
		} else {
			t.SafeClose(conn)
		}
	}
}
