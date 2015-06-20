package tunnel

import (
	"fmt"
	ex "github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	d5p           *D5Params
	ctl           *CtlThread
	mux           *multiplexer
	token         []byte
	cipherFactory *CipherFactory
	lock          sync.Locker
	aliveTT       int32
	waitTk        *sync.Cond
	State         int32 // -1:aborted 0:working 1:token requesting
}

func NewClient(d5p *D5Params, dhKeys *DHKeyPair, exitHandler CtlExitHandler) *Client {
	// new d5CNegotiation and set parameters
	nego := new(d5CNegotiation)
	nego.D5Params = d5p
	nego.dhKeys = dhKeys
	nego.algoId = d5p.algoId
	// connect to server
	ctlConn := nego.negotiate()
	ctlConn.SetSockOpt(1, 1, 1)
	log.Infof("Negotiated the tunnel with gateway %s successfully.\n", ctlConn.identifier)
	me := &Client{
		d5p:   d5p,
		token: nego.token,
		lock:  new(sync.Mutex),
	}
	me.waitTk = sync.NewCond(me.lock)
	me.cipherFactory = nego.cipherFactory
	var exitHandlerCallback CtlExitHandler = func() {
		// flag: negative State
		// 1, for some blocking tunSession to abort.
		// 2, for skipping when selecting client
		atomic.StoreInt32(&me.State, -1)
		log.Warningf("Lost connection of backend %s, then will reconnect.\n", d5p.RemoteId())
		exitHandler()
	}
	me.ctl = NewCtlThread(ctlConn, int(nego.interval))
	go me.ctl.start(me.commandHandler, exitHandlerCallback)
	me.startConnPool()
	return me
}

// TODO start by ctl event
func (this *Client) startConnPool() {
	this.mux = NewClientMultiplexer()
	var tdc onTunDisconnectedCallback = func(old *Conn) {
		if old != nil {
			time.Sleep(time.Second)
		}
		if atomic.LoadInt32(&this.State) >= 0 {
			bconn := this.createTunnel()
			go this.mux.Listen(bconn, this.ctl)
		}
	}
	this.mux.onTDC = tdc
	// TODO need server parameters
	for i := 0; i < 3; i++ {
		tdc(nil)
	}
}

func (this *Client) ClientServe(conn net.Conn) {
	var done bool
	defer func() {
		ex.CatchException(recover())
		atomic.AddInt32(&this.aliveTT, -1)
		if !done {
			SafeClose(conn)
		}
	}()

	s5 := S5Step1{conn: conn}
	s5.Handshake()
	if !s5.HandshakeAck() {
		target_str := s5.parseSocks5Request()
		if log.V(1) {
			log.Infoln("Socks5 ->", target_str, "from", conn.RemoteAddr())
		}

		if !s5.respondSocks5() {
			atomic.AddInt32(&this.aliveTT, 1)
			this.mux.HandleRequest(conn, s5.target, target_str)
			done = true
		}
	}
}

func (this *Client) createTunnel() *Conn {
	conn, err := net.DialTCP("tcp", nil, this.d5p.d5sAddr)
	ThrowErr(err)
	buf := make([]byte, SzTk+1)
	token := this.getToken()
	copy(buf, token)
	buf[SzTk] = byte(D5 - int(int8(token[SzTk-1])))

	cipher := this.cipherFactory.NewCipher(token)
	_, err = conn.Write(buf)
	ThrowErr(err)
	c := NewConn(conn, cipher)
	c.identifier = this.d5p.RemoteId()
	return c
}

func (t *Client) Stats() string {
	return fmt.Sprintf("Stats/Client To-%s TT=%d TK=%d", t.d5p.d5sAddrStr,
		atomic.LoadInt32(&t.aliveTT), len(t.token)/SzTk)
}

func (this *Client) getToken() []byte {
	this.lock.Lock()
	defer func() {
		this.lock.Unlock()
		tlen := len(this.token) / SzTk
		if tlen <= 8 && atomic.LoadInt32(&this.State) == 0 {
			atomic.AddInt32(&this.State, 1)
			if log.V(2) {
				log.Infof("Request new tokens, pool=%d\n", tlen)
			}
			this.ctl.postCommand(TOKEN_REQUEST, nil)
		}
	}()
	for len(this.token) < SzTk {
		if log.V(2) {
			log.Infoln("waiting for token. May be the requests came too fast, or that responded slowly.")
		}
		this.waitTk.Wait()
		if atomic.LoadInt32(&this.State) < 0 {
			panic("Abandon the request beacause the tunSession was lost.")
		}
	}
	token := this.token[:SzTk]
	this.token = this.token[SzTk:]

	return token
}

func (this *Client) putTokens(tokens []byte) {
	defer this.lock.Unlock()
	this.lock.Lock()
	this.token = append(this.token, tokens...)
	atomic.StoreInt32(&this.State, 0)
	this.waitTk.Broadcast()
	log.Infof("Recv tokens=%d pool=%d\n", len(tokens)/SzTk, len(this.token)/SzTk)
}

func (this *Client) commandHandler(cmd byte, args []byte) {
	switch cmd {
	case TOKEN_REPLY:
		this.putTokens(args)
	default:
		log.Warningf("Unrecognized command=%x packet=[% x]\n", cmd, args)
	}
}
