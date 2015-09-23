package main

import (
	"flag"
	"fmt"
	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/golang/glog"
	t "github.com/Lafeng/deblocus/tunnel"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DH_METHOD = "ECDHE-P256"
)

type Statser interface {
	Stats() string
}

type bootContext struct {
	config    string
	isServ    bool
	csc       bool
	ccc       bool
	statser   Statser
	verbosity string
	debug     bool
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
			fmt.Println("No such file", c.config)
			fmt.Println("Create/put config in typical path or indicate it explicitly.")
			os.Exit(1)
		}
	}
	t.VERSION = version
	t.VER_STRING = versionString()
	t.DEBUG = c.debug
	ex.DEBUG = c.debug
}

func (c *bootContext) doStats() {
	if c.statser != nil {
		println(c.statser.Stats())
	}
}

func (c *bootContext) setLogVerbose(level int) {
	var vFlag = c.verbosity
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

func (c *bootContext) ccc_process(output string) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Println(e)
		}
	}()
	if flag.NArg() >= 2 {
		addr := flag.Arg(0)
		if v, e := t.IsValidHost(addr); !v {
			panic(e)
		}
		var d5sc = t.Parse_d5sFile(c.config)
		d5sc.Listen = addr
		for i, arg := range flag.Args() {
			if i > 0 {
				t.CreateClientConfig(output, d5sc, arg)
			}
		}
		return
	} else {
		fmt.Println("Which user do you issue client credential for?")
	}
}

type clientMgr struct {
	dhKey      t.DHKE
	d5pArray   []*t.D5Params
	clients    []*t.Client
	num        int
	indexChain []byte
}

func (m *clientMgr) selectClient() *t.Client {
	if m.num > 1 {
		i := rand.Intn(m.num<<4) >> 4
		for _, v := range m.indexChain[i : i+m.num-1] {
			if w := m.clients[v]; w != nil && atomic.LoadInt32(&w.State) >= 0 {
				return w
			}
		}
	} else {
		if w := m.clients[0]; w != nil && atomic.LoadInt32(&w.State) >= 0 {
			return w
		}
	}
	log.Errorf("No available tunnels for servicing new request")
	time.Sleep(t.REST_INTERVAL)
	return nil
}

func (m *clientMgr) selectClientServ(conn net.Conn) {
	if client := m.selectClient(); client != nil {
		client.ClientServe(conn)
	} else {
		t.SafeClose(conn)
	}
}

func (m *clientMgr) Stats() string {
	arr := make([]string, m.num)
	for i, c := range m.clients {
		if c != nil {
			arr[i] = c.Stats()
		}
	}
	return strings.Join(arr, "\n")
}

func NewClientMgr(d5c *t.D5ClientConf) *clientMgr {
	d5pArray := d5c.D5PList
	dhKey, _ := t.NewDHKey(DH_METHOD)
	num := len(d5pArray)
	var chain []byte
	if num > 1 {
		chain = make([]byte, 2*num)
		for i, _ := range chain {
			chain[i] = byte(i % num)
		}
	}
	mgr := &clientMgr{
		dhKey,
		d5pArray,
		make([]*t.Client, num),
		num,
		chain,
	}

	for i := 0; i < num; i++ {
		c := t.NewClient(d5pArray[i], dhKey)
		mgr.clients[i] = c
		go c.StartTun(true)
	}
	return mgr
}

func (context *bootContext) startClient() {
	defer func() {
		ex.CatchException(warning(recover()))
		sigChan <- t.Bye
	}()
	var conf = t.Parse_d5cFile(context.config)
	context.setLogVerbose(conf.Verbose)
	log.Infoln(versionString())
	log.Infoln("Socks5/Http is working at", conf.ListenAddr)

	mgr := NewClientMgr(conf)
	context.statser = mgr

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

func (context *bootContext) startServer() {
	defer func() {
		ex.CatchException(warning(recover()))
		sigChan <- t.Bye
	}()
	var conf = t.Parse_d5sFile(context.config)
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

func warning(e interface{}) interface{} {
	if err, y := e.(error); y {
		// 0.9.x to 0.10.x config error
		if strings.HasPrefix(err.Error(), "Unrecognized directives") {
			log.Warningf("Please read %s/wiki to learn more.", project_url)
		}
	}
	return e
}
