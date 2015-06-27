package main

import (
	"sync/atomic"
	//ex "github.com/spance/deblocus/exception"
	"fmt"
	log "github.com/spance/deblocus/golang/glog"
	t "github.com/spance/deblocus/tunnel"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

type Statser interface {
	Stats() string
}

type bootContext struct {
	config    string
	isServ    bool
	csc       bool
	icc       bool
	statser   Statser
	verbosity string
}

func (c *bootContext) parse() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	if !c.isServ {
		c.isServ = c.icc || t.DetectRunAsServ()
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

type clientMgr struct {
	dhKeys     *t.DHKeyPair
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
	time.Sleep(time.Second)
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
	dhKeys := t.GenerateDHKeyPairs()
	num := len(d5pArray)
	var chain []byte
	if num > 1 {
		chain = make([]byte, 2*num)
		for i, _ := range chain {
			chain[i] = byte(i % num)
		}
	}
	mgr := &clientMgr{
		dhKeys,
		d5pArray,
		make([]*t.Client, num),
		num,
		chain,
	}

	for i := 0; i < num; i++ {
		c := t.NewClient(d5pArray[i], dhKeys)
		mgr.clients[i] = c
		go c.StartSigTun(false)
	}
	return mgr
}
