package main

import (
	"flag"
	"fmt"
	log "github.com/Lafeng/deblocus/golang/glog"
	t "github.com/Lafeng/deblocus/tunnel"
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
	flag.StringVar(&context.config, "config", "", "indicate Config path if it in nontypical path")
	flag.StringVar(&output, "o", "", "output file")
	flag.BoolVar(&context.csc, "csc", false, "Server;;Create Server Config")
	flag.BoolVar(&context.icc, "icc", false, "Server;;Issue Client Credential for user//-icc <ServerAddress:Port> <User1> <User2>...")
	flag.BoolVar(&context.isServ, "serv", false, "Server;;run as Server explicitly")
	flag.BoolVar(&showVersion, "V", false, "show Version")
	flag.StringVar(&context.verbosity, "v", "", "Verbose log level")
	flag.StringVar(&logDir, "logdir", "", "write log into the directory")
	flag.BoolVar(&context.debug, "debug", false, "debug")
	flag.Parse()

	if showVersion {
		fmt.Println(versionString())
		return
	}

	context.parse()
	// toStd bool, logDir string
	log.Set_output(true, logDir)

	if context.csc {
		t.Generate_d5sFile(output, nil)
		return
	}

	if context.icc {
		context.icc_process(output)
		return
	}

	if context.isServ {
		go context.startServer()
	} else {
		go context.startClient()
	}
	waitSignal()
}
