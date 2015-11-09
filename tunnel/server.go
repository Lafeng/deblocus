package tunnel

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/Lafeng/deblocus/crypto"
	ex "github.com/Lafeng/deblocus/exception"
	"github.com/Lafeng/deblocus/geo"
	log "github.com/Lafeng/deblocus/golang/glog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	GENERATE_TOKEN_NUM = 4
	TOKENS_FLOOR       = 2
	PARALLEL_TUN_QTY   = 2
	TKSZ               = sha1.Size
)

//
//
//
//  Session
//
//
//
type Session struct {
	mux           *multiplexer
	mgr           *SessionMgr
	uid           string // user
	cid           string // client
	cipherFactory *CipherFactory
	tokens        map[string]bool
	activeCnt     int32
}

func NewSession(tun *Conn, cf *CipherFactory, n *dbcSerNego) *Session {
	s := &Session{
		mux:           newServerMultiplexer(),
		mgr:           n.sessionMgr,
		cipherFactory: cf,
		tokens:        make(map[string]bool),
	}
	s.uid = SubstringBefore(n.clientIdentity, IDENTITY_SEP)
	s.cid = SubstringLastBefore(s.identifyConn(tun), ":")
	if n.Server.filter != nil {
		s.mux.filter = n.Server.filter
	}
	return s
}

func (s *Session) identifyConn(c *Conn) string {
	if c.identifier == NULL {
		// unique in server instance
		c.identifier = fmt.Sprintf("%s@%s", s.uid, c.RemoteAddr())
	}
	return c.identifier
}

func (t *Session) eventHandler(e event, msg ...interface{}) {
	switch e {
	case evt_tokens:
		go t.tokensHandle(msg[0].([]byte))
	}
}

func (t *Session) tokensHandle(args []byte) {
	var cmd = args[0]
	switch cmd {
	case FRAME_ACTION_TOKEN_REQUEST:
		tokens := t.mgr.createTokens(t, GENERATE_TOKEN_NUM)
		if tokens != nil {
			tokens[0] = FRAME_ACTION_TOKEN_REPLY
			t.mux.bestSend(tokens, "replyTokens")
		}
	default:
		log.Warningf("Unrecognized command=%x packet=[% x]\n", cmd, args)
	}
}

func (t *Session) DataTunServe(tun *Conn, isNewSession bool) {
	defer func() {
		tun.cipher.Cleanup()
		if atomic.AddInt32(&t.activeCnt, -1) <= 0 {
			t.destroy()
			log.Infof("Client %s was offline", t.cid)
		}
	}()

	if isNewSession {
		log.Infof("Client %s is online", t.cid)
	}
	if log.V(1) {
		log.Infof("Tun %s is established", tun.identifier)
	}
	cnt := atomic.AddInt32(&t.activeCnt, 1)
	// mux will output error log
	t.mux.Listen(tun, t.eventHandler, DT_PING_INTERVAL+int(cnt))
	if log.V(1) {
		log.Infof("Tun %s was disconnected", tun.identifier)
	}
}

func (t *Session) destroy() {
	t.cipherFactory.Cleanup()
	t.mgr.clearTokens(t)
	t.mux.destroy()
}

//
//
//
type SessionContainer map[string]*Session

//
//
//
//  SessionMgr
//
//
//
type SessionMgr struct {
	container SessionContainer
	lock      *sync.RWMutex
}

func NewSessionMgr() *SessionMgr {
	return &SessionMgr{
		container: make(SessionContainer),
		lock:      new(sync.RWMutex),
	}
}

func (s *SessionMgr) take(token []byte) *Session {
	s.lock.Lock()
	defer s.lock.Unlock()
	key := fmt.Sprintf("%x", token)
	ses := s.container[key]
	delete(s.container, key)
	if ses != nil {
		delete(ses.tokens, key)
	}
	return ses
}

func (s *SessionMgr) length() int {
	return len(s.container)
}

func (s *SessionMgr) clearTokens(session *Session) int {
	s.lock.Lock()
	defer s.lock.Unlock()
	var i = len(session.tokens)
	for k, _ := range session.tokens {
		delete(s.container, k)
	}
	session.tokens = nil
	return i
}

// return header=1 + TKSZ*many
func (s *SessionMgr) createTokens(session *Session, many int) []byte {
	s.lock.Lock()
	defer s.lock.Unlock()

	// issue #35
	// clearTokens() invoked prior to createTokens()
	if session == nil || session.tokens == nil {
		return nil
	}

	var (
		tokens  = make([]byte, 1+many*TKSZ)
		i64buf  = make([]byte, 8)
		_tokens = tokens[1:]
		sha     = sha1.New()
	)
	rand.Seed(time.Now().UnixNano())
	sha.Write([]byte(session.uid))
	for i := 0; i < many; i++ {
		binary.BigEndian.PutUint64(i64buf, uint64(rand.Int63()))
		sha.Write(i64buf)
		binary.BigEndian.PutUint64(i64buf, uint64(time.Now().UnixNano()))
		sha.Write(i64buf)
		pos := i * TKSZ
		sha.Sum(_tokens[pos:pos])
		token := _tokens[pos : pos+TKSZ]
		key := fmt.Sprintf("%x", token)
		if _, y := s.container[key]; y {
			i--
			continue
		}
		s.container[key] = session
		session.tokens[key] = true
	}
	if log.V(4) {
		log.Errorf("sessionMap created=%d len=%d\n", many, len(s.container))
	}
	return tokens
}

//
//
//
//  Server
//
//
//
type Server struct {
	*D5ServConf
	dhKey      crypto.DHKE
	sharedKey  []byte
	sessionMgr *SessionMgr
	tunParams  *tunParams
	tcPool     unsafe.Pointer // *[]uint64
	tcTicker   *time.Ticker
	filter     Filterable
}

func NewServer(d5s *D5ServConf, dhKey crypto.DHKE) *Server {
	s := &Server{
		D5ServConf: d5s,
		dhKey:      dhKey,
		sharedKey:  d5s.rsaKey.SharedKey(),
		sessionMgr: NewSessionMgr(),
		tunParams: &tunParams{
			pingInterval: DT_PING_INTERVAL,
			parallels:    PARALLEL_TUN_QTY,
		},
	}

	// inital update time counter
	s.updateNow()

	var step = time.Second * TIME_STEP
	var now = time.Now()
	// Calculate the distance to next integral minute,
	var dis = now.Truncate(step).Add(step).Sub(now).Nanoseconds() - 1e3
	if dis < 1e3 {
		dis = 1e3
	}

	// To make the discrete time-counter closer to the exact zero point of minute.
	// then plan starting the timer on next integral minutes.
	time.AfterFunc(time.Duration(dis), func() {
		s.updateNow() // first run on integral point manully
		go s.updateTimeCounterWorker(step)
	})

	if len(d5s.DenyDest) == 2 {
		s.filter, _ = geo.NewGeoIPFilter(d5s.DenyDest)
	}
	return s
}

func (t *Server) TunnelServe(raw *net.TCPConn) {
	hConn, conn := newHashedConn(raw)
	defer func() {
		ex.CatchException(recover())
	}()

	nego := &dbcSerNego{
		Server:     t,
		clientAddr: raw.RemoteAddr(),
	}
	// read atomically
	tcPool := *(*[]uint64)(atomic.LoadPointer(&t.tcPool))
	session, err := nego.negotiate(hConn, tcPool)

	if err == nil {
		go session.DataTunServe(conn, nego.isNewSession)
	} else {
		SafeClose(raw)
		if session != nil {
			t.sessionMgr.clearTokens(session)
		}
	}
}

func (s *Server) updateTimeCounterWorker(step time.Duration) {
	if s.tcTicker == nil {
		s.tcTicker = time.NewTicker(step)
	}
	// awakened by ticker to do second and later
	for now := range s.tcTicker.C {
		s.updateNow()
		myRand.setSeed(now.Nanosecond())
	}
}

func (s *Server) updateNow() {
	tc := calculateTimeCounter(true)
	// write atomically
	atomic.StorePointer(&s.tcPool, unsafe.Pointer(&tc))
	if log.V(4) {
		log.Infoln("updateTimeCounterThread", len(tc))
	}
}

// implement Stats()
func (t *Server) Stats() string {
	uniqClient := make(map[string]byte)
	t.sessionMgr.lock.RLock()
	for _, s := range t.sessionMgr.container {
		if _, y := uniqClient[s.cid]; !y {
			uniqClient[s.cid] = byte(s.activeCnt)
		}
	}
	t.sessionMgr.lock.RUnlock()
	buf := new(bytes.Buffer)
	for k, n := range uniqClient {
		buf.WriteString(fmt.Sprintf("Clt=%s Conn=%d\n", k, n))
	}
	return string(buf.Bytes())
}

// implement Close()
func (t *Server) Close() {
	uniqSession := make(map[string]byte)
	for _, s := range t.sessionMgr.container {
		if _, y := uniqSession[s.cid]; !y {
			uniqSession[s.cid] = 1
			s.destroy()
		}
	}
}

//
// filter interface ,eg. GeoFilter
//
type Filterable interface {
	Filter(host string) bool
}
