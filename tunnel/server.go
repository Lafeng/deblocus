package tunnel

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	ex "github.com/Lafeng/deblocus/exception"
	"github.com/Lafeng/deblocus/geo"
	log "github.com/Lafeng/deblocus/golang/glog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
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
		tokens[0] = FRAME_ACTION_TOKEN_REPLY
		t.mux.bestSend(tokens, "replyTokens")
	default:
		log.Warningf("Unrecognized command=%x packet=[% x]\n", cmd, args)
	}
}

func (t *Session) DataTunServe(fconn *Conn, isNewSession bool) {
	atomic.AddInt32(&t.activeCnt, 1)
	defer func() {
		var (
			offline bool
			err     = recover()
		)
		if atomic.AddInt32(&t.activeCnt, -1) <= 0 {
			offline = true
			t.mgr.clearTokens(t)
			t.mux.destroy()
		}
		if log.V(1) {
			log.Infof("Tun=%s was disconnected. %v\n", fconn.identifier, nvl(err, NULL))
			if offline {
				log.Infof("Client=%s was offline\n", t.cid)
			}
		}
		if DEBUG {
			ex.CatchException(err)
		}
	}()
	if isNewSession {
		log.Infof("Client=%s is online\n", t.cid)
	}

	if log.V(1) {
		log.Infof("Tun=%s is established\n", fconn.identifier)
	}
	t.mux.Listen(fconn, t.eventHandler, DT_PING_INTERVAL)
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
	dhKey      DHKE
	sessionMgr *SessionMgr
	filter     Filterable
}

func NewServer(d5s *D5ServConf, dhKey DHKE) *Server {
	s := &Server{d5s, dhKey, NewSessionMgr(), nil}
	if len(d5s.DenyDest) == 2 {
		s.filter, _ = geo.NewGeoIPFilter(d5s.DenyDest)
	}
	return s
}

func (t *Server) TunnelServe(conn *net.TCPConn) {
	hConn := newHashedConn(conn)
	defer func() {
		hConn.FreeHash()
		ex.CatchException(recover())
	}()
	nego := &dbcSerNego{Server: t}
	session, err := nego.negotiate(hConn)

	if err == nil {
		go session.DataTunServe(hConn.Conn, nego.isNewSession)
	} else {
		SafeClose(conn)
		if session != nil {
			t.sessionMgr.clearTokens(session)
		}
	}
}

func (t *Server) Stats() string {
	return ""
}

//
// filter interface ,eg. GeoFilter
//
type Filterable interface {
	Filter(host string) bool
}
