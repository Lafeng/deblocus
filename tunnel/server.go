package tunnel

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	ex "github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	GENERATE_TOKEN_NUM = 16
	TOKENS_FLOOR       = 8
	PARALLEL_TUN_QTY   = 3
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
	svr           *Server
	tun           *Conn
	uid           string
	cipherFactory *CipherFactory
	tokens        map[string]bool
	sigTun        *signalTunnel
}

func NewSession(tun *Conn, cf *CipherFactory, identity string) *Session {
	sep := strings.IndexByte(identity, 0)
	var uid string
	if sep > 0 {
		uid = identity[:sep]
	} else {
		uid = identity
	}
	return &Session{
		tun:           tun,
		uid:           uid,
		cipherFactory: cf,
		tokens:        make(map[string]bool),
	}
}
func (t *Session) eventHandler(e event, msg ...interface{}) {
	var mlen = len(msg)
	switch e {
	case evt_st_msg:
		if mlen == 1 {
			go t.commandHandler(msg[0].(byte), nil)
		} else {
			go t.commandHandler(msg[0].(byte), msg[1].([]byte))
		}
	case evt_st_closed:
		t.onSTDisconnected()
	case evt_st_active:
		t.sigTun.active(msg[0].(int64))
	}
}

func (t *Session) onSTDisconnected() {
	tid := IdentifierOf(t.tun)
	SafeClose(t.tun)
	atomic.AddInt32(&t.svr.stCnt, -1)
	log.Warningln("Client", tid, "disconnected")
	i := t.svr.sessionMgr.clearTokens(t)
	if log.V(4) {
		log.Infof("Clear tokens %d of %s\n", i, tid)
	}
}

func (t *Session) commandHandler(cmd byte, args []byte) {
	switch cmd {
	case TOKEN_REQUEST:
		tokens := t.svr.sessionMgr.createTokens(t, GENERATE_TOKEN_NUM)
		t.sigTun.postCommand(TOKEN_REPLY, tokens)
	default:
		log.Warningf("Unrecognized command=%x packet=[% x]\n", cmd, args)
	}
}

func (t *Session) DataTunServe(fconn *Conn, buf []byte) {
	var svr = t.svr
	defer func() {
		atomic.AddInt32(&svr.dtCnt, -1)
		SafeClose(fconn)
		ex.CatchException(recover())
	}()
	atomic.AddInt32(&svr.dtCnt, 1)
	token := buf[:TKSZ]
	fconn.cipher = t.cipherFactory.NewCipher(token)
	// unique
	fconn.identifier = fmt.Sprintf("%s(%s)", t.uid, fconn.RemoteAddr())
	log.Infoln(fconn.identifier, "client/DT established")
	svr.mux.Listen(fconn, t.eventHandler, DT_PING_INTERVAL)
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

func (s *SessionMgr) createTokens(session *Session, many int) []byte {
	s.lock.Lock()
	defer s.lock.Unlock()
	tokens := make([]byte, many*TKSZ)
	i64buf := make([]byte, 8)
	sha := sha1.New()
	rand.Seed(time.Now().UnixNano())
	sha.Write([]byte(session.uid))
	for i := 0; i < many; i++ {
		binary.BigEndian.PutUint64(i64buf, uint64(rand.Int63()))
		sha.Write(i64buf)
		binary.BigEndian.PutUint64(i64buf, uint64(time.Now().UnixNano()))
		sha.Write(i64buf)
		pos := i * TKSZ
		sha.Sum(tokens[pos:pos])
		token := tokens[pos : pos+TKSZ]
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
	dhKeys     *DHKeyPair
	sessionMgr *SessionMgr
	mux        *multiplexer
	dtCnt      int32
	stCnt      int32
}

func NewServer(d5s *D5ServConf, dhKeys *DHKeyPair) *Server {
	return &Server{
		d5s, dhKeys, NewSessionMgr(), NewServerMultiplexer(), 0, 0,
	}
}

func (t *Server) TunnelServe(conn *net.TCPConn) {
	fconn := NewConnWithHash(conn)
	defer func() {
		fconn.FreeHash()
		ex.CatchException(recover())
	}()
	nego := &d5SNegotiation{Server: t}
	session, err := nego.negotiate(fconn)

	if err != nil {
		if err == DATATUN_SESSION { // dataTunnel
			go session.DataTunServe(fconn.Conn, nego.tokenBuf)
		} else {
			log.Warningln("Close abnormal connection from", conn.RemoteAddr(), err)
			SafeClose(conn)
			if session != nil {
				t.sessionMgr.clearTokens(session)
			}
		}
	} else if session != nil { // signalTunnel
		log.Infoln(session.uid, conn.RemoteAddr(), "client/ST established")
		atomic.AddInt32(&t.stCnt, 1)
		fconn.SetSockOpt(1, 0, 1)
		var st = NewSignalTunnel(session.tun, 0)
		session.svr = t
		session.sigTun = st
		go st.start(session.eventHandler)
	}
}

func (t *Server) Stats() string {
	return fmt.Sprintf("Stats/Server ST=%d DT=%d TK=%d",
		atomic.LoadInt32(&t.stCnt), atomic.LoadInt32(&t.dtCnt), t.sessionMgr.length())
}
