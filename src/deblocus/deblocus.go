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

var sigChan = make(chan os.Signal, 1)

func waitSignal() {
	signal.Notify(sigChan)
	for sig := range sigChan {
		switch sig {
		case t.Bye:
			return
		case syscall.SIGINT, syscall.SIGTERM:
			log.Infoln("Terminated by signal", sig)
			return
		default:
			log.Infoln("Ingore signal", sig)
		}
	}
}

func main() {
	var context = &bootContext{}
	var output string
	var icc bool
	flag.StringVar(&context.listen, "l", "", "listen on [HOST]:PORT")
	flag.StringVar(&context.config, "config", "", "indicate the unconventional path")
	flag.StringVar(&output, "o", "", "output file")
	flag.BoolVar(&context.csc, "csc", false, "Create Server Config")
	flag.BoolVar(&icc, "icc", false, "Issue Client Credential for user")
	flag.BoolVar(&context.isServ, "serv", false, "Run as server explicitly or InitialCap")
	flag.Parse()
	context.parse()
	log.Set_toStderr(true)

	if context.csc {
		t.Generate_d5sFile(output, nil)
		return
	}

	if icc {
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
	//defer func() {
	//	ex.CatchException(recover())
	//	sigChan <- t.Bye
	//}()
	d5c := t.Parse_d5cFile(context.config)
	mgr := NewClientMgr(d5c)
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
	for {
		conn, err := ln.AcceptTCP()
		if err == nil {
			go server.TunnelServe(conn)
		}
	}
}
