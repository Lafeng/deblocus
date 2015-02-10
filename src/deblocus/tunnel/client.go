package tunnel

import (
	ex "deblocus/exception"
	"fmt"
	log "golang/glog"
	"net"
	"sync"
	"sync/atomic"
)

var client_sid int32

type Client struct {
	d5p           *D5Params
	ctl           *CtlThread
	token         []byte
	cipherFactory *CipherFactory
	lock          sync.Locker
	aliveTT       int32
	waitTk        *sync.Cond
	State         int32 // -1:aborted 0:working 1:token requesting
}

func NewClient(d5p *D5Params, dhKeys *DHKeyPair, exitHandler CtlExitHandler) *Client {
	nego := new(d5CNegotiation)
	nego.D5Params = d5p
	nego.dhKeys = dhKeys
	nego.algoId = d5p.algoId
	ctlConn := nego.negotiate()
	ctlConn.SetSockOpt(1, 1, 1)
	log.Infof("Backend %s is ready.\n", ctlConn.identifier)
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
	return me
}

func (this *Client) ClientServe(conn net.Conn) {
	var bconn *Conn
	var done bool
	defer func() {
		ex.CatchException(recover())
		atomic.AddInt32(&this.aliveTT, -1)
		if !done {
			SafeClose(conn)
			SafeClose(bconn)
		}
	}()
	if log.V(2) {
		log.Infoln("Request/socks5 from", conn.RemoteAddr().String())
	}
	s5 := S5Step1{conn: conn}
	s5.Handshake()
	if !s5.HandshakeAck() {
		target := s5.parseSocks5Request()
		if !s5.respondSocks5() {
			sid := atomic.AddInt32(&client_sid, 1)
			bconn = this.createTunnel(sid, s5.target)
			bconn.SetSockOpt(-1, 0, 0)
			bconn.identifier = this.d5p.RemoteId()
			log.Infof("SID#%X connect to %s via %s\n", sid, target, bconn.identifier)
			atomic.AddInt32(&this.aliveTT, 1)
			go Pipe(conn, bconn, sid, this.ctl)
			Pipe(bconn, conn, sid, this.ctl)
			done = true
		}
	}
}

func (this *Client) createTunnel(sid int32, target []byte) *Conn {
	conn, err := net.DialTCP("tcp", nil, this.d5p.d5sAddr)
	ThrowErr(err)
	buf := make([]byte, DMLEN)
	token := this.getToken(sid)
	copy(buf, token)
	copy(buf[TT_TOKEN_OFFSET:], token) // TT_TOKEN_OFFSET
	copy(buf[TT_TOKEN_OFFSET+SzTk:], target)
	// |-----------------DMLEN----------------|
	// | token~20 | enc:token~20 | s5target~? |
	buf[SzTk] = token[SzTk-1]
	buf[SzTk+1] = D5
	cipher := this.cipherFactory.NewCipher(token)
	cipher.encrypt(buf[TT_TOKEN_OFFSET:], buf[TT_TOKEN_OFFSET:])
	_, err = conn.Write(buf)
	ThrowErr(err)
	return NewConn(conn, cipher)
}

func (t *Client) Stats() string {
	return fmt.Sprintf("Stats/Client To-%s TT=%d TK=%d", t.d5p.d5sAddrStr,
		atomic.LoadInt32(&t.aliveTT), len(t.token)/SzTk)
}

func (this *Client) getToken(sid int32) []byte {
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
	this.lock.Lock()
	for len(this.token) < SzTk {
		if log.V(2) {
			log.Infof("SID#%X waiting for token. May be the requests came too fast, or that responded slowly.\n", sid)
		}
		this.waitTk.Wait()
		if atomic.LoadInt32(&this.State) < 0 {
			panic("Abandon the request beacause the tunSession was lost.")
		}
	}
	token := this.token[:SzTk]
	this.token = this.token[SzTk:]
	if log.V(3) {
		tlen := len(this.token) / SzTk
		log.Infof("SID#%X take token=%x pool=%d\n", sid, token, tlen)
	}
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
