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
	RETRY_INTERVAL = time.Second * 5
)

type Client struct {
	sigTun      *signalTunnel
	mux         *multiplexer
	token       []byte
	nego        *d5CNegotiation
	tp          *tunParams
	lock        sync.Locker
	dtCnt       int32
	State       int32 // -1:aborted 0:working 1:requesting token
	waitTK      *sync.Cond
	pendingSema *semaphore
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
		lock:        new(sync.Mutex),
		nego:        new(d5CNegotiation),
		pendingSema: NewSemaphore(),
	}
	clt.waitTK = sync.NewCond(clt.lock)
	// set parameters
	clt.nego.D5Params = d5p
	clt.nego.dhKeys = dhKeys
	return clt
}

func (c *Client) StartSigTun(again bool) {
	defer func() {
		if err := recover(); err != nil {
			c.eventHandler(evt_st_closed, true)
		} else {
			c.eventHandler(evt_st_ready, c.sigTun.tun.identifier)
		}
	}()
	if again {
		/*
			if c.mux != nil {
				c.mux.destroy()
				if c.mux.status == MUX_CLOSED {
					c.mux = nil
				}
			}
		*/
		time.Sleep(RETRY_INTERVAL)
	}
	stConn, tp := c.nego.negotiate()
	stConn.identifier = c.nego.RemoteName()
	c.tp, c.token = tp, tp.token
	c.sigTun = NewSignalTunnel(stConn, tp.stInterval)
	go c.sigTun.start(c.eventHandler)
}

// when sigTun is ready
func (c *Client) startMultiplexer() {
	if c.mux == nil {
		c.mux = NewClientMultiplexer()
		for i := c.tp.tunQty; i > 0; i-- {
			go c.startDataTun(false)
		}
	} else {
		c.pendingSema.notifyAll()
	}
}

func (c *Client) startDataTun(again bool) {
	var connected bool
	defer func() {
		if connected {
			atomic.AddInt32(&c.dtCnt, -1)
		}
		if err := recover(); err != nil {
			log.Warningf("DTun failed to connect(%s). Retry after %s\n", err, RETRY_INTERVAL)
			c.eventHandler(evt_dt_closed, true)
		}
	}()
	if again {
		time.Sleep(RETRY_INTERVAL)
	}
	for {
		if atomic.LoadInt32(&c.State) == 0 {
			conn := c.createDataTun()
			connected = true
			if log.V(1) {
				log.Infof("DTun(%s) is established\n", conn.sign())
			}
			atomic.AddInt32(&c.dtCnt, 1)
			c.mux.Listen(conn, c.eventHandler, c.tp.dtInterval)
			log.Warningf("DTun(%s) was disconnected. Reconnect after %s\n", conn.sign(), RETRY_INTERVAL)
			break
		} else {
			c.pendingSema.acquire(RETRY_INTERVAL)
		}
	}
}

func (c *Client) eventHandler(e event, msg ...interface{}) {
	var mlen = len(msg)
	switch e {
	case evt_st_closed:
		atomic.StoreInt32(&c.State, -1)
		c.clearTokens()
		log.Warningf("Lost connection of gateway %s. Reconnect after %s\n", c.nego.RemoteName(), RETRY_INTERVAL)
		go c.StartSigTun(mlen > 0)
	case evt_st_ready:
		atomic.StoreInt32(&c.State, 0)
		log.Infoln("Tunnel negotiated with gateway", msg[0], "successfully")
		go c.startMultiplexer()
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
		if !done {
			SafeClose(conn)
		}
	}()

	pbConn := NewPushbackInputStream(conn)
	switch detectProtocol(pbConn) {
	case REQ_PROT_SOCKS5:
		s5 := S5Step1{conn: pbConn}
		s5.Handshake()
		if !s5.HandshakeAck() {
			literalTarget := s5.parseSocks5Request()
			if !s5.respondSocks5() {
				c.mux.HandleRequest(conn, literalTarget)
				done = true
			}
		}
	case REQ_PROT_HTTP:
		literalTarget := httpProxyHandshake(pbConn)
		if pbConn.HasRemains() {
			c.mux.HandleRequest(pbConn, literalTarget)
		} else {
			c.mux.HandleRequest(conn, literalTarget)
		}
		done = true
	default:
		log.Warningln("unrecognized request from", conn.RemoteAddr())
		time.Sleep(3 * time.Second)
	}

}

func (t *Client) createDataTun() *Conn {
	conn, err := net.DialTimeout("tcp", t.nego.d5sAddr.String(), FRAME_OPEN_TIMEOUT/2)
	ThrowErr(err)
	buf := make([]byte, DMLEN2)
	token := t.getToken()
	copy(buf, token)
	buf[TKSZ] = d5Sub(token[TKSZ-2])
	buf[TKSZ+1] = d5Sub(token[TKSZ-1])

	cipher := t.tp.cipherFactory.NewCipher(token)
	_, err = conn.Write(buf)
	ThrowErr(err)
	c := NewConn(conn.(*net.TCPConn), cipher)
	c.identifier = t.nego.RemoteName()
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
			if log.V(4) {
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
	if log.V(4) {
		log.Infof("Recv tokens=%d pool=%d\n", len(tokens)/TKSZ, len(c.token)/TKSZ)
	}
}

func (c *Client) clearTokens() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.token = nil
}

func (c *Client) commandHandler(cmd byte, args []byte) {
	switch cmd {
	case TOKEN_REPLY:
		c.putTokens(args)
	default:
		log.Warningf("Unrecognized command=%x packet=[% x]\n", cmd, args)
	}
}
