package tunnel

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/glog"
)

const (
	DT_PING_INTERVAL = 110
	RETRY_INTERVAL   = time.Second * 5
	REST_INTERVAL    = RETRY_INTERVAL
)

const (
	CLT_CLOSED  int32 = -1
	CLT_WORKING int32 = 0
	CLT_PENDING int32 = 1
)

var (
	ERR_REQ_TK_TIMEOUT = ex.New("Request token timeout")
	ERR_REQ_TK_ABORTED = ex.New("Requst token aborted")
)

type Client struct {
	mux       *multiplexer
	token     []byte
	params    *tunParams
	connInfo  *connectionInfo
	lock      sync.Locker
	dtCnt     int32
	reqCnt    int32
	state     int32
	round     int32
	pendingTK *timedWait
}

func NewClient(cman *ConfigMan) *Client {
	clt := &Client{
		lock:      new(sync.Mutex),
		connInfo:  cman.cConf.connInfo,
		state:     CLT_WORKING,
		pendingTK: NewTimedWait(false), // waiting tokens
	}
	return clt
}

func (c *Client) initialConnect() (tun *Conn) {
	var theParam = new(tunParams)
	var man = &d5cman{connectionInfo: c.connInfo}
	var err error
	tun, err = man.Connect(theParam)
	if err != nil {
		log.Errorf("Failed to connect to %s %s Retry after %s",
			c.connInfo.RemoteName(), ex.Detail(err), RETRY_INTERVAL)
		return nil
	} else {
		log.Infof("Login to server %s with %s successfully",
			c.connInfo.RemoteName(), c.connInfo.user)
		c.params = theParam
		c.token = theParam.token
		return
	}
}

func (c *Client) restart() (tun *Conn, rn int32) {
	// discard requests are waiting for tokens
	c.pendingTK.clearAll()
	// release mux
	if c.mux != nil {
		// spin wait for all mux.Listen() goroutines exits
		for atomic.LoadInt32(&c.dtCnt) > 0 {
			time.Sleep(time.Second)
		}
		c.mux.destroy()
	}
	c.mux = newClientMultiplexer()
	// try negotiating connection infinitely until success
	for i := 0; tun == nil; i++ {
		if i > 0 {
			time.Sleep(RETRY_INTERVAL)
		}
		tun = c.initialConnect()
	}
	atomic.StoreInt32(&c.state, CLT_WORKING)
	rn = atomic.AddInt32(&c.round, 1)
	// start n-1 data tun
	for j := c.params.parallels; j > 1; j-- {
		go c.StartTun(false)
	}
	return
}

func (c *Client) StartTun(mustRestart bool) {
	var (
		tun  *Conn
		wait bool
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
			// clear mustRestart
			mustRestart = false
			tun, rn = c.restart()
		}
		if atomic.LoadInt32(&c.state) == CLT_WORKING {
			var dtcnt int32
			var err error

			// not restarting, ordinary data tun
			if tun == nil {
				tun, err = c.createDataTun()
				if err != nil {
					log.Errorf("Connection failed %s Reconnect after %s",
						ex.Detail(err), RETRY_INTERVAL)
					wait = true
					continue
				}
			}

			if log.V(log.LV_CLT_CONNECT) {
				log.Infof("Tun %s is established", tun.identifier)
			}

			dtcnt = atomic.AddInt32(&c.dtCnt, 1)
			err = c.mux.Listen(tun, c.eventHandler, c.params.pingInterval+int(dtcnt))
			dtcnt = atomic.AddInt32(&c.dtCnt, -1)

			if log.V(log.LV_CLT_CONNECT) {
				log.Errorf("Tun %s was disconnected %s Reconnect after %s",
					tun.identifier, ex.Detail(err), RETRY_INTERVAL)
			}
			// reset
			tun, wait = nil, true

			// received ping count
			if atomic.LoadInt32(&c.mux.pingCnt) <= 0 {
				// dirty tokens: used abandoned tokens
				c.clearTokens()
			}

			// restart: all connections were disconnected
			if dtcnt <= 0 {
				if atomic.CompareAndSwapInt32(&c.state, CLT_WORKING, CLT_PENDING) {
					log.Errorf("Currently offline, all connections %s were lost",
						c.connInfo.RemoteName())
					go c.StartTun(true)
				}
				return
			}
		} else {
			// now is restarting then exit
			return
		}
	}
}

func (c *Client) ClientServe(conn net.Conn) {
	var done bool
	defer func() {
		ex.Catch(recover(), nil)
		if !done {
			SafeClose(conn)
		}
	}()

	reqNum := atomic.AddInt32(&c.reqCnt, 1)
	pbConn := NewPushbackInputStream(conn)
	proto, err := detectProtocol(pbConn)
	if err != nil {
		// chrome will make some advance connections and then aborted
		// cause a EOF
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			log.Warningln(err)
		}
		return
	}

	switch proto {
	case PROT_SOCKS5:
		s5 := socks5Handler{pbConn}
		if s5.handshake() {
			if literalTarget, ok := s5.readRequest(); ok {
				c.mux.HandleRequest("SOCKS5", conn, literalTarget)
				done = true
			}
		}
	case PROT_HTTP:
		proto, target, err := httpProxyHandshake(pbConn)
		if err != nil {
			log.Warningln(err)
			break
		}
		switch proto {
		case PROT_HTTP:
			// plain http
			c.mux.HandleRequest("HTTP", pbConn, target)
		case PROT_HTTP_T:
			// http tunnel
			c.mux.HandleRequest("HTTP/T", conn, target)
		case PROT_LOCAL:
			// target is requestUri
			c.localServlet(conn, target)
		}
		done = true
	default:
		log.Warningln("Unrecognized request from", conn.RemoteAddr())
		time.Sleep(REST_INTERVAL)
	}
	// client setSeed at every 32 req
	if reqNum&0x1f == 0x1f {
		myRand.setSeed(0)
	}
}

func (t *Client) IsReady() bool {
	return atomic.LoadInt32(&t.dtCnt) > 0
}

func (t *Client) createDataTun() (c *Conn, err error) {
	var token []byte
	token, err = t.getToken()
	if err != nil {
		return
	}
	man := &d5cman{connectionInfo: t.connInfo}
	return man.ResumeSession(t.params, token)
}

func (c *Client) eventHandler(e event, msg ...interface{}) {
	switch e {
	case evt_tokens:
		go c.saveTokens(msg[0].([]byte))
	}
}

func (t *Client) Stats() string {
	return fmt.Sprintf("Client -> %s Conn=%d TK=%d",
		t.connInfo.sAddr, atomic.LoadInt32(&t.dtCnt), len(t.token)/TKSZ)
}

func (t *Client) Close() {
	if t.mux != nil {
		t.mux.destroy()
	}
	if t.params != nil {
		f := t.params.cipherFactory
		if f != nil {
			f.Cleanup()
		}
	}
}

func (c *Client) getToken() ([]byte, error) {
	c.lock.Lock()

	var tlen = len(c.token) / TKSZ
	if tlen <= TOKENS_FLOOR {
		// TODO may request many times
		c.asyncRequestTokens()
	}
	for len(c.token) < TKSZ {
		// release lock for waiting of pendingTK()
		c.lock.Unlock()
		log.Warningln("Waiting for token. Maybe the requests are coming too fast.")
		if !c.pendingTK.await(RETRY_INTERVAL * 2) {
			// acquire() cancelled by clearAll()
			return nil, ERR_REQ_TK_TIMEOUT
		}
		if atomic.LoadInt32(&c.state) < CLT_WORKING {
			return nil, ERR_REQ_TK_ABORTED
		}
		// recover lock status
		c.lock.Lock()
	}
	var token = c.token[:TKSZ]
	c.token = c.token[TKSZ:]
	// finally release
	c.lock.Unlock()
	return token, nil
}

// async request
func (c *Client) asyncRequestTokens() {
	// don't require if shutdown
	if atomic.LoadInt32(&c.state) >= CLT_WORKING {
		go c.mux.bestSend([]byte{FRAME_ACTION_TOKEN_REQUEST}, "asyncRequestTokens")
		if log.V(log.LV_TOKEN) {
			log.Infof("Request new tokens, current pool=%d\n", len(c.token)/TKSZ)
		}
	}
}

func (c *Client) saveTokens(data []byte) {
	var tokens []byte
	switch data[0] {
	case FRAME_ACTION_TOKEN_REQUEST:
		log.Warningf("Unexpected token request")
		return
	case FRAME_ACTION_TOKEN_REPLY:
		tokens = data[1:]
	}
	c.lock.Lock()
	c.token = append(c.token, tokens...)
	c.lock.Unlock()
	// wakeup waiting
	c.pendingTK.notifyAll()
	if log.V(log.LV_TOKEN) {
		log.Infof("Received tokens=%d pool=%d\n", len(tokens)/TKSZ, len(c.token)/TKSZ)
	}
}

func (c *Client) clearTokens() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.token = nil
}
