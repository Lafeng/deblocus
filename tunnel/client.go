package tunnel

import (
	"fmt"
	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/golang/glog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DT_PING_INTERVAL = 90
	RETRY_INTERVAL   = time.Second * 5
	REST_INTERVAL    = RETRY_INTERVAL
)

const (
	CLT_CLOSED  int32 = -1
	CLT_WORKING int32 = 0
	CLT_PENDING int32 = 1
)

type Client struct {
	mux         *multiplexer
	token       []byte
	nego        *dbcCltNego
	tp          *tunParams
	lock        sync.Locker
	dtCnt       int32
	State       int32
	restarting  int32
	round       int32
	pendingConn *semaphore
	pendingTK   *semaphore
}

func NewClient(d5p *D5Params, dhKey DHKE) *Client {
	clt := &Client{
		lock:        new(sync.Mutex),
		nego:        &dbcCltNego{D5Params: d5p, dhKey: dhKey},
		State:       CLT_PENDING,
		pendingConn: NewSemaphore(true), // unestablished connection
		pendingTK:   NewSemaphore(true), // waiting tokens
	}
	return clt
}

func (c *Client) initialNegotiation() (tun *Conn) {
	var tp = new(tunParams)
	var err error
	tun, err = c.nego.negotiate(tp)
	if err != nil {
		log.Errorf("Failed to connect %s, Retry after %s\n", c.nego.RemoteName(), RETRY_INTERVAL)
		return nil
	}
	c.token, c.tp = tp.token, tp
	tp.token = nil
	tun.identifier = c.nego.RemoteName()

	log.Infoln("Login to the gateway", c.nego.RemoteName(), "successfully")
	return tun
}

// start first negotiation
// start n-1 data tun
func (c *Client) restart() (tun *Conn, rn int32) {
	if atomic.CompareAndSwapInt32(&c.restarting, 0, 1) {
		// discard old conn retrying
		c.pendingConn.clearAll()
		// discard requests are waiting for tokens
		c.pendingTK.clearAll()
		// release mux
		if c.mux != nil {
			c.mux.destroy()
		}
		c.mux = newClientMultiplexer()
		// try negotiating connection infinitely until success
		for i := 0; tun == nil; i++ {
			if i > 0 {
				time.Sleep(RETRY_INTERVAL)
			}
			tun = c.initialNegotiation()
		}
		atomic.CompareAndSwapInt32(&c.restarting, 1, 0)
		atomic.CompareAndSwapInt32(&c.State, CLT_PENDING, CLT_WORKING)
		rn = atomic.AddInt32(&c.round, 1)
		for j := c.tp.tunQty; j > 1; j-- {
			go c.StartTun(false)
		}
	}
	return
}

func (c *Client) StartTun(mustRestart bool) {
	var (
		wait bool
		tun  *Conn
		rn   = atomic.LoadInt32(&c.round)
	)
	for {
		if wait {
			time.Sleep(RETRY_INTERVAL)
		}
		if rn < atomic.LoadInt32(&c.round) {
			return
		}
		if mustRestart {
			mustRestart = false
			if atomic.SwapInt32(&c.State, CLT_PENDING) >= CLT_WORKING {
				tun, rn = c.restart()
				if tun == nil {
					return
				}
			} else {
				return
			}
		}
		if atomic.LoadInt32(&c.State) == CLT_WORKING {
			// negotiation conn executed here firstly will not be null
			// otherwise must be null then create new one.
			if tun == nil {
				var err error
				tun, err = c.createDataTun()
				if err != nil {
					if DEBUG {
						ex.CatchException(err)
					}
					log.Errorf("Failed to connect %s. Reconnect after %s\n", err, RETRY_INTERVAL)
					wait = true
					continue
				}
			}

			if log.V(1) {
				log.Infof("Tun=%s is established\n", tun.sign())
			}
			atomic.AddInt32(&c.dtCnt, 1)
			c.mux.Listen(tun, c.eventHandler, c.tp.dtInterval)
			dtcnt := atomic.AddInt32(&c.dtCnt, -1)

			log.Errorf("Tun=%s was disconnected, Reconnect after %s\n", tun.sign(), RETRY_INTERVAL)

			if atomic.LoadInt32(&c.mux.pingCnt) <= 0 { // dirty tokens: used abandoned tokens
				c.clearTokens()
			}

			if dtcnt <= 0 { // restart: all connections were disconnected
				log.Errorf("Connections %s were lost\n", tun.identifier)
				go c.StartTun(true)
				return
			} else { // reconnect
				// waiting and don't use old tun
				wait = true
				tun = nil
			}
		} else { // can't create tun and waiting for release
			if !c.pendingConn.acquire(RETRY_INTERVAL) {
				return
			}
		}
	}
}

func (c *Client) ClientServe(conn net.Conn) {
	var done bool
	defer func() {
		if e := recover(); e != nil {
			log.Warningln(e)
		}
		if !done {
			SafeClose(conn)
		}
	}()

	pbConn := NewPushbackInputStream(conn)
	proto, e := detectProtocol(pbConn)
	if e != nil {
		log.Warningln(e)
		return
	}
	switch proto {
	case REQ_PROT_SOCKS5:
		s5 := s5Handler{conn: pbConn}
		s5.handshake()
		if !s5.handshakeResponse() {
			literalTarget := s5.parseRequest()
			if !s5.finalResponse() {
				c.mux.HandleRequest("SOCKS5", conn, literalTarget)
				done = true
			}
		}
	case REQ_PROT_HTTP:
		prot, literalTarget := httpProxyHandshake(pbConn)
		if prot == REQ_PROT_HTTP { // plain http
			c.mux.HandleRequest("HTTP", pbConn, literalTarget)
		} else { // http tunnel
			c.mux.HandleRequest("HTTP/T", conn, literalTarget)
		}
		done = true
	default:
		log.Warningln("unrecognized request from", conn.RemoteAddr())
		time.Sleep(REST_INTERVAL)
	}

}

// must catch exceptions and return
func (t *Client) createDataTun() (c *Conn, err error) {
	defer func() {
		if e, y := ex.ErrorOf(recover()); y {
			err = e
		}
	}()
	conn, err := net.DialTimeout("tcp", t.nego.d5sAddrStr, GENERAL_SO_TIMEOUT)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, DMLEN2)
	token := t.getToken()
	copy(buf, token)
	buf[TKSZ] = d5Sub(token[TKSZ-2])
	buf[TKSZ+1] = d5Sub(token[TKSZ-1])

	cipher := t.tp.cipherFactory.InitCipher(token)
	_, err = conn.Write(buf)
	ThrowErr(err)
	c = NewConn(conn.(*net.TCPConn), cipher)
	c.identifier = t.nego.RemoteName()
	return c, nil
}

func (c *Client) eventHandler(e event, msg ...interface{}) {
	switch e {
	case evt_tokens:
		go c.saveTokens(msg[0].([]byte))
	}
}

func (t *Client) Stats() string {
	return fmt.Sprintf("Stats/Client -> %s DT=%d TK=%d", t.nego.d5sAddrStr,
		atomic.LoadInt32(&t.dtCnt), len(t.token)/TKSZ)
}

func (c *Client) getToken() []byte {
	c.lock.Lock()
	defer c.lock.Unlock()

	var tlen = len(c.token) / TKSZ
	if tlen <= TOKENS_FLOOR {
		c.requireTokens()
	}
	for len(c.token) < TKSZ {
		log.Warningln("waiting for token. May be the requests are coming too fast.")
		if !c.pendingTK.acquire(RETRY_INTERVAL * 2) { // discarded request
			panic("Aborted")
		}
		if atomic.LoadInt32(&c.State) < CLT_WORKING {
			panic("Abandon the request by shutdown.")
		}
	}
	var token = c.token[:TKSZ]
	c.token = c.token[TKSZ:]
	return token
}

// async request
func (c *Client) requireTokens() {
	// non-working state can't require anything
	if atomic.CompareAndSwapInt32(&c.State, CLT_WORKING, CLT_PENDING) {
		if log.V(3) {
			log.Infof("Request new tokens, pool=%d\n", len(c.token)/TKSZ)
		}
		go c.mux.bestSend([]byte{FRAME_ACTION_TOKEN_REQUEST}, "requireTokens")
	}
}

func (c *Client) saveTokens(data []byte) {
	var tokens []byte
	switch data[0] {
	case FRAME_ACTION_TOKEN_REQUEST:
		log.Warningf("unexpected token request")
		return
	case FRAME_ACTION_TOKEN_REPLY:
		tokens = data[1:]
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.token = append(c.token, tokens...)
	atomic.CompareAndSwapInt32(&c.State, CLT_PENDING, CLT_WORKING)
	c.pendingTK.notifyAll()
	if log.V(3) {
		log.Infof("Recv tokens=%d pool=%d\n", len(tokens)/TKSZ, len(c.token)/TKSZ)
	}
}

func (c *Client) clearTokens() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.token = nil
}
