package tunnel

import (
	"bytes"
	"fmt"
	"github.com/Lafeng/deblocus/crypto"
	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/golang/glog"
	"io"
	"net"
	"os"
	"strings"
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

var (
	ERR_REQ_TK_TIMEOUT = ex.NewW("Request token timeout")
	ERR_REQ_TK_ABORTED = ex.NewW("Requst token aborted")
)

type Client struct {
	mux         *multiplexer
	token       []byte
	nego        *dbcCltNego
	params      *tunParams
	lock        sync.Locker
	dtCnt       int32
	state       int32
	round       int32
	pendingConn *semaphore
	pendingTK   *semaphore
}

func NewClient(d5c *D5ClientConf, dhKey crypto.DHKE) *Client {
	clt := &Client{
		lock:        new(sync.Mutex),
		nego:        &dbcCltNego{D5Params: d5c.d5p, dhKey: dhKey},
		state:       CLT_WORKING,
		pendingConn: NewSemaphore(true), // unestablished connection
		pendingTK:   NewSemaphore(true), // waiting tokens
	}
	return clt
}

func (c *Client) initialNegotiation() (tun *Conn) {
	var newParams = new(tunParams)
	var err error
	tun, err = c.nego.negotiate(newParams)
	if err != nil {
		if log.V(1) == true || DEBUG {
			log.Errorf("Connection failed %s, Error: %s. Retry after %s",
				c.nego.RemoteName(), err, RETRY_INTERVAL)
		} else {
			log.Errorf("Connection failed %s. Retry after %s",
				c.nego.RemoteName(), RETRY_INTERVAL)
		}
		if strings.Contains(err.Error(), "closed") {
			log.Warningln(string(bytes.Repeat([]byte{'+'}, 30)))
			log.Warningln("Maybe your clock is inaccurate, or your client credential is invalid.")
			log.Warningln(string(bytes.Repeat([]byte{'+'}, 30)))
			os.Exit(2)
		}
		return nil
	}
	c.params = newParams
	c.token = newParams.token

	tun.identifier = c.nego.RemoteName()
	log.Infof("Login to the gateway %s successfully", tun.identifier)
	return
}

func (c *Client) restart() (tun *Conn, rn int32) {
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
			// clear mustRestart
			mustRestart = false
			// prevent concurrently
			if atomic.CompareAndSwapInt32(&c.state, CLT_WORKING, CLT_PENDING) {
				tun, rn = c.restart()
			} else {
				return
			}
		}
		if atomic.LoadInt32(&c.state) == CLT_WORKING {
			// negotiation conn executed here firstly will not be null
			// otherwise must be null then create new one.
			if tun == nil {
				var err error
				tun, err = c.createDataTun()
				if err != nil {
					if log.V(1) == true || DEBUG {
						log.Errorf("Connection failed %s, Error: %s. Reconnect after %s",
							c.nego.RemoteName(), err, RETRY_INTERVAL)
					} else {
						log.Errorf("Connection failed %s. Reconnect after %s",
							c.nego.RemoteName(), RETRY_INTERVAL)
					}
					wait = true
					continue
				}
			}

			if log.V(1) {
				log.Infof("Tun %s is established\n", tun.sign())
			}

			atomic.AddInt32(&c.dtCnt, 1)
			c.mux.Listen(tun, c.eventHandler, c.params.pingInterval)
			dtcnt := atomic.AddInt32(&c.dtCnt, -1)

			log.Errorf("Tun %s was disconnected, Reconnect after %s\n", tun.sign(), RETRY_INTERVAL)

			tun.cipher.Cleanup()
			if atomic.LoadInt32(&c.mux.pingCnt) <= 0 {
				// dirty tokens: used abandoned tokens
				c.clearTokens()
			}

			if dtcnt <= 0 { // restart: all connections were disconnected
				log.Errorf("Connections %s were lost\n", tun.identifier)
				go c.StartTun(true)
				return

			} else { // reconnect
				// don't use old tun
				wait, tun = true, nil
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
		// chrome will make some advance connections and then aborted
		// cause a EOF
		if e != io.EOF && e != io.ErrUnexpectedEOF {
			log.Warningln(e)
		}
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

func (t *Client) IsReady() bool {
	return atomic.LoadInt32(&t.dtCnt) > 0
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

	var buf = new(bytes.Buffer)
	obf := makeDbcHead(TYPE_DAT, t.nego.rsaKey.SharedKey())
	buf.Write(obf)

	var token []byte
	token, err = t.getToken()
	if err != nil {
		return nil, err
	}
	buf.Write(token)

	setWTimeout(conn)
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}

	cipher := t.params.cipherFactory.InitCipher(token)
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
	return fmt.Sprintf("Client -> %s Conn=%d TK=%d", t.nego.d5sAddrStr,
		atomic.LoadInt32(&t.dtCnt), len(t.token)/TKSZ)
}

func (t *Client) Close() {
	t.mux.destroy()
	if f := t.params.cipherFactory; f != nil {
		f.Cleanup()
	}
}

func (c *Client) getToken() ([]byte, error) {
	c.lock.Lock()

	var tlen = len(c.token) / TKSZ
	if tlen <= TOKENS_FLOOR {
		c.asyncRequestTokens()
	}
	for len(c.token) < TKSZ {
		// release lock for waiting of pendingTK()
		c.lock.Unlock()
		log.Warningln("Waiting for token. Maybe the requests are coming too fast.")
		if !c.pendingTK.acquire(RETRY_INTERVAL * 2) {
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
		if log.V(3) {
			log.Infof("Request new tokens, pool=%d\n", len(c.token)/TKSZ)
		}
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
	c.token = append(c.token, tokens...)
	c.lock.Unlock()
	// wakeup waiting
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
