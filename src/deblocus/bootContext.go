package main

import (
	ex "deblocus/exception"
	t "deblocus/tunnel"
	"fmt"
	log "golang/glog"
	"math/rand"
	"net"
	"os"
	"runtime"
	"time"
)

type bootContext struct {
	listen string
	config string
	isServ bool
	csc    bool
}

func (c *bootContext) parse() {
	if !c.isServ {
		c.isServ = t.DetectRunAsServ()
	}
	if c.config == "" && !c.csc {
		var e bool
		c.config, e = t.DetectFile(c.isServ)
		if !e {
			fmt.Println("No such file", c.config)
			fmt.Println("Create/put config in conventional path or indicate it explicitly.")
			os.Exit(1)
		}
	}
	if c.isServ {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}
}

type clientMgr struct {
	dhKeys   *t.DHKeyPair
	d5pArray []*t.D5Params
	clients  []*t.Client
	num      int
	seqCycle []byte
}

func (m *clientMgr) selectClient() *t.Client {
	for {
		if m.num > 1 {
			i := rand.Intn(m.num<<4) >> 4
			for _, v := range m.seqCycle[i : i+m.num-1] {
				w := m.clients[v]
				if w != nil {
					return w
				}
			}
		} else {
			w := m.clients[0]
			if w != nil {
				return w
			}
		}
		log.Warningln("No available client for new connection, will try again after 5s")
		time.Sleep(5 * time.Second)
	}
}

func (m *clientMgr) selectClientServ(conn net.Conn) {
	m.selectClient().ClientServe(conn)
}

func (m *clientMgr) rebuildClient(seq int) *t.Client {
	defer ex.CatchException(recover())
	var exitHandler t.CtlExitHandler = func(addr string) {
		m.clients[seq] = nil
		log.Errorf("Client->%s disconnected, will reconnect.", addr)
		m.rebuildClient(seq)
	}
	time.Sleep(3 * time.Second)
	d5p := m.d5pArray[seq]
	client := t.NewClient(d5p, m.dhKeys, exitHandler)
	m.clients[seq] = client
	return client
}

func NewClientMgr(d5c *t.D5ClientConf) *clientMgr {
	d5pArray := d5c.D5PList
	dhKeys := t.GenerateDHKeyPairs()
	num := len(d5pArray)
	var cycle []byte
	if num > 1 {
		cycle = make([]byte, 2*num)
		for i, _ := range cycle {
			cycle[i] = byte(i % num)
		}
	}
	mgr := &clientMgr{
		dhKeys,
		d5pArray,
		make([]*t.Client, num),
		num,
		cycle,
	}

	for i := 0; i < num; i++ {
		mgr.clients[i] = mgr.rebuildClient(i)
	}
	return mgr
}
