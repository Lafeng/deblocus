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

const (
	RETRY_INTERVAL = time.Second * 3
)

type Client struct {
	sigTun *signalTunnel
	mux    *multiplexer
	token  []byte
	nego   *d5CNegotiation
	tp     *tunParams
	lock   sync.Locker
	retry  uint32
	dtCnt  int32
	State  int32 // -1:aborted 0:working 1:token requesting
	waitTK *sync.Cond
}

type event byte

var (
	evt_st_closed = event(0)
	evt_st_ready  = event(1)
	evt_st_msg    = event(4)
	evt_st_active = event(5)
	evt_dt_closed = event(2)
	evt_dt_ready  = event(3)
)

type event_handler func(e event, msg ...interface{})

func NewClient(d5p *D5Params, dhKeys *DHKeyPair) *Client {
	clt := &Client{
		lock: new(sync.Mutex),
		nego: new(d5CNegotiation),
	}
	clt.waitTK = sync.NewCond(clt.lock)
	// set parameters
	clt.nego.D5Params = d5p
	clt.nego.dhKeys = dhKeys
	return clt
}

func (c *Client) StartSigTun() {
	defer func() {
		if ex.CatchException(recover()) {
			c.eventHandler(evt_st_closed)
		}
	}()
	if c.retry > 0 {
		log.Warningln("Will retry after", RETRY_INTERVAL)
		time.Sleep(RETRY_INTERVAL)
	}
	stConn, tp := c.nego.negotiate()
	// connected
	defer c.eventHandler(evt_st_ready, stConn.identifier)
	stConn.SetSockOpt(1, 1, 1)
	c.tp, c.token = tp, tp.token
	c.sigTun = NewSignalTunnel(stConn, tp.interval)
	go c.sigTun.start(c.eventHandler)
}

func (c *Client) startMultiplexer() {
	c.mux = NewClientMultiplexer()
	// TODO need server parameters
	for i := 0; i < 3; i++ {
		go c.startDataTun(false)
	}
}

func (c *Client) startDataTun(again bool) {
	defer func() {
		if ex.CatchException(recover()) {
			c.eventHandler(evt_dt_closed, true)
		}
	}()
	if again {
		log.Warningln("DTun was disconnected then will reconnect after", RETRY_INTERVAL)
		time.Sleep(RETRY_INTERVAL)
	}
	if atomic.LoadInt32(&c.State) >= 0 {
		bconn := c.createDataTun()
		c.mux.Listen(bconn, c.eventHandler)
	}
}

func (c *Client) eventHandler(e event, msg ...interface{}) {
	var mlen = len(msg)
	switch e {
	case evt_st_closed:
		atomic.StoreInt32(&c.State, -1)
		atomic.AddUint32(&c.retry, 1)
		log.Warningln("Lost connection of gateway", c.nego.RemoteId())
		go c.StartSigTun()
	case evt_st_ready:
		atomic.StoreInt32(&c.State, 0)
		atomic.StoreUint32(&c.retry, 0)
		log.Infoln("Tunnel negotiated with gateway", msg[0], "successfully")
		if c.mux == nil {
			go c.startMultiplexer()
		}
	case evt_dt_closed:
		go c.startDataTun(mlen > 0)
	case evt_st_msg:
		if mlen == 1 {
			go c.commandHandler(msg[0].(byte), nil)
		} else {
			go c.commandHandler(msg[0].(byte), msg[1].([]byte))
		}
	case evt_st_active:
		c.sigTun.active(msg[0].(int64))
	}
}

func (c *Client) ClientServe(conn net.Conn) {
	var done bool
	defer func() {
		ex.CatchException(recover())
		atomic.AddInt32(&c.dtCnt, -1)
		if !done {
			SafeClose(conn)
		}
	}()

	s5 := S5Step1{conn: conn}
	s5.Handshake()
	if !s5.HandshakeAck() {
		literalTarget := s5.parseSocks5Request()
		if !s5.respondSocks5() {
			atomic.AddInt32(&c.dtCnt, 1)
			c.mux.HandleRequest(conn, literalTarget)
			done = true
		}
	}
}

func (t *Client) createDataTun() *Conn {
	conn, err := net.DialTCP("tcp", nil, t.nego.d5sAddr)
	ThrowErr(err)
	buf := make([]byte, TKSZ+1)
	token := t.getToken()
	copy(buf, token)
	buf[TKSZ] = byte(D5 - int(int8(token[TKSZ-1])))

	cipher := t.tp.cipherFactory.NewCipher(token)
	_, err = conn.Write(buf)
	ThrowErr(err)
	c := NewConn(conn, cipher)
	c.identifier = t.nego.RemoteId()
	return c
}

func (t *Client) Stats() string {
	return fmt.Sprintf("Stats/Client -> %s DT=%d TK=%d", t.nego.d5sAddrStr,
		atomic.LoadInt32(&t.dtCnt), len(t.token)/TKSZ)
}

func (c *Client) getToken() []byte {
	c.lock.Lock()
	defer func() {
		c.lock.Unlock()
		tlen := len(c.token) / TKSZ
		if tlen <= TOKENS_FLOOR && atomic.LoadInt32(&c.State) == 0 {
			atomic.AddInt32(&c.State, 1)
			if log.V(3) {
				log.Infof("Request new tokens, pool=%d\n", tlen)
			}
			c.sigTun.postCommand(TOKEN_REQUEST, nil)
		}
	}()
	for len(c.token) < TKSZ {
		log.Warningln("waiting for token. May be the requests are coming too fast.")
		c.waitTK.Wait()
		if atomic.LoadInt32(&c.State) < 0 {
			panic("Abandon the request beacause the tunSession was lost.")
		}
	}
	token := c.token[:TKSZ]
	c.token = c.token[TKSZ:]

	return token
}

func (c *Client) putTokens(tokens []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.token = append(c.token, tokens...)
	atomic.StoreInt32(&c.State, 0)
	c.waitTK.Broadcast()
	if log.V(3) {
		log.Infof("Recv tokens=%d pool=%d\n", len(tokens)/TKSZ, len(c.token)/TKSZ)
	}
}

func (c *Client) commandHandler(cmd byte, args []byte) {
	switch cmd {
	case TOKEN_REPLY:
		c.putTokens(args)
	default:
		log.Warningf("Unrecognized command=%x packet=[% x]\n", cmd, args)
	}
}
