package main

import (
	"flag"
	"fmt"
	ex "github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	t "github.com/spance/deblocus/tunnel"
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
		case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			log.Exitln("Terminated by", sig)
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
	flag.StringVar(&context.config, "config", "", "indicate Config if in nontypical path")
	flag.StringVar(&output, "o", "", "output file")
	flag.BoolVar(&context.csc, "csc", false, "Server;;Create Server Config")
	flag.BoolVar(&context.icc, "icc", false, "Server;;Issue Client Credential for user//-icc <Server public address> <User1> <User2>...")
	flag.BoolVar(&context.isServ, "serv", false, "Server;;run as Server explicitly")
	flag.BoolVar(&showVersion, "V", false, "show Version")
	flag.StringVar(&context.verbosity, "v", "", "Verbose log level")
	flag.StringVar(&logDir, "logdir", "", "if non-empty will write log into the Directory")
	flag.Parse()

	if showVersion {
		fmt.Println(versionString())
		return
	}

	context.parse()
	log.Set_output(true, logDir)

	if context.csc {
		t.Generate_d5sFile(output, nil)
		return
	}

	if context.icc {
		context.csc_process(output)
		return
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
	log.Infoln("Socks5/Http is working at", conf.ListenAddr)

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
	log.Infoln("Server is listening on", conf.ListenAddr)

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
