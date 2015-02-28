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

const (
	RETRY_INTERVAL = 5
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
	if c.isServ {
		runtime.GOMAXPROCS(runtime.NumCPU())
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
	log.Errorf("No available connection of backend for servicing new request")
	// sleep to prevent a lot of new connections come into.
	time.Sleep(5 * time.Second)
	// no better way reliably detect remote was closed
	// so just take null then close self
	return nil
}

func (m *clientMgr) selectClientServ(conn net.Conn) {
	if client := m.selectClient(); client != nil {
		client.ClientServe(conn)
	} else {
		t.SafeClose(conn)
	}
}

func (m *clientMgr) rebuildClient(index, try int) {
	var d5p = m.d5pArray[index]
	defer func() {
		err := recover()
		if err != nil {
			log.Errorln("Failed to connect to backend", d5p.RemoteIdFull(), err)
			go m.rebuildClient(index, try<<1)
		}
	}()
	var exitHandler t.CtlExitHandler = func() {
		m.clients[index] = nil
		m.rebuildClient(index, 1)
	}
	if try > 1 {
		if try > 60 {
			try = 60
		}
		var times = time.Duration(try*RETRY_INTERVAL) * time.Second
		log.Warningf("Will retry after %s.\n", times)
		time.Sleep(times)
	}
	m.clients[index] = t.NewClient(d5p, m.dhKeys, exitHandler)
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
		mgr.rebuildClient(i, 1)
	}
	return mgr
}
