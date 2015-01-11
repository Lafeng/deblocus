package tunnel

import (
	"crypto/sha1"
	ex "deblocus/exception"
	"encoding/binary"
	"fmt"
	log "golang/glog"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	GENERATE_TOKEN_NUM = 64
	SzTk               = sha1.Size
	TOKEN_REQUEST      = byte(5)
	TOKEN_REPLY        = byte(6)
)

type SessionCtType map[string]*Session

func NewSessionMgr() *SessionMgr {
	return &SessionMgr{
		container: make(SessionCtType),
		lock:      new(sync.RWMutex),
	}
}

type SessionMgr struct {
	container SessionCtType
	lock      *sync.RWMutex
}

func (s *SessionMgr) take(token []byte) *Session {
	defer s.lock.Unlock()
	s.lock.Lock()
	key := fmt.Sprintf("%x", token)
	ses := s.container[key]
	delete(s.container, key)
	if ses != nil {
		delete(ses.tokens, key)
	}
	return ses
}

func (s *SessionMgr) length() int {
	//defer s.lock.RUnlock()
	//s.lock.RLock()
	return len(s.container)
}

func (s *SessionMgr) clearTokens(session *Session) {
	defer s.lock.Unlock()
	s.lock.Lock()
	for k, _ := range session.tokens {
		delete(s.container, k)
	}
}

func (s *SessionMgr) createTokens(session *Session, many int) []byte {
	defer s.lock.Unlock()
	s.lock.Lock()
	tokens := make([]byte, many*SzTk)
	i64buf := make([]byte, 8)
	sha := sha1.New()
	rand.Seed(time.Now().UnixNano())
	sha.Write([]byte(session.identity))
	for i := 0; i < many; i++ {
		binary.BigEndian.PutUint64(i64buf, uint64(rand.Int63()))
		sha.Write(i64buf)
		binary.BigEndian.PutUint64(i64buf, uint64(time.Now().UnixNano()))
		sha.Write(i64buf)
		pos := i * SzTk
		sha.Sum(tokens[pos:pos])
		token := tokens[pos : pos+SzTk]
		key := fmt.Sprintf("%x", token)
		if _, y := s.container[key]; y {
			i--
			continue
		}
		s.container[key] = session
		session.tokens[key] = true
	}
	log.Errorf("sessionMap created=%d len=%d\n", many, len(s.container))
	return tokens
}

type Server struct {
	*D5ServConf
	dhKeys     *DHKeyPair
	sessionMgr *SessionMgr
	sid        int32
	aliveTT    int32
	aliveCT    int32
}

func NewServer(d5s *D5ServConf, dhKeys *DHKeyPair) *Server {
	return &Server{
		d5s, dhKeys, NewSessionMgr(), 0, 0, 0,
	}
}

func (t *Server) TunnelServe(conn *net.TCPConn) {
	defer ex.CatchException(recover())
	nego := &d5SNegotiation{Server: t}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fconn := NewConnWithHash(conn)
	session, err := nego.negotiate(fconn)
	if err == TRANS_SESSION {
		sid := atomic.AddInt32(&t.sid, 1)
		log.Infof("Serving SID#%X client=%s@%s\n", sid, session.uid, conn.RemoteAddr())
		t.TransServe(fconn, session.cipherFactory.NewCipher(), nego.remnant, sid)
		return
	}
	if err != nil {
		log.Warningln("Close abnormal connection from ", conn.RemoteAddr(), err)
		SafeClose(conn)
		return
	}
	if session != nil {
		atomic.AddInt32(&t.aliveCT, 1)
		fconn.NoDelayAlive()
		var ser_cmdHandler CtlCommandHandler = func(cmd byte, args []byte) {
			switch cmd {
			case TOKEN_REQUEST:
				tokens := t.sessionMgr.createTokens(session, GENERATE_TOKEN_NUM)
				postCommand(session.tun, TOKEN_REPLY, tokens)
			default:
				log.Warningf("Unrecognized command=%x packet=[% x]\n", cmd, args)
			}
		}
		var ser_exitHandler CtlExitHandler = func(addr string) {
			log.Warningf("CtlTun->%s disconnected.\n", addr)
			t.sessionMgr.clearTokens(session)
			session.tokens = nil
			SafeClose(session.tun)
			atomic.AddInt32(&t.aliveCT, -1)
		}
		go RControlThread(fconn, ser_cmdHandler, ser_exitHandler)
	}
}

func (t *Server) TransServe(fconn *Conn, cipher *Cipher, remnant []byte, sid int32) {
	defer func() {
		SafeClose(fconn)
		ex.CatchException(recover())
		atomic.AddInt32(&t.aliveTT, -1)
	}()
	atomic.AddInt32(&t.aliveTT, 1)
	s5 := new(S5Target)
	cipher.decrypt(remnant, remnant)
	//dumpHex("remnant", remnant)
	remnant = remnant[SzTk:]
	target, err := s5.parseSocks5Target(remnant)
	if err != nil {
		log.Errorf("SID#%X Failed to connect to %s[%s] [%s]\n", sid, s5.host, s5.dst, err)
	} else {
		fconn.cipher = cipher
		log.Infof("SID#%X Connect to %s[%s] is established\n", sid, s5.host, s5.dst)
		go Pipe(target, fconn, sid)
		Pipe(fconn, target, sid)
	}
}

func (t *Server) Stats() string {
	return fmt.Sprintf("Server:Stats CT=%d TT=%d TM=%d",
		atomic.LoadInt32(&t.aliveCT), atomic.LoadInt32(&t.aliveTT), t.sessionMgr.length())
}

type Session struct {
	tun           *Conn
	identity      string
	uid           string
	cipherFactory *CipherFactory
	tokens        map[string]bool
}

func postCommand(tun *Conn, cmd byte, args []byte) (int, error) {
	buf := make([]byte, 4)
	buf[0] = cmd
	binary.BigEndian.PutUint16(buf[2:], uint16(len(args)))
	if args != nil {
		buf = append(buf, args...)
	}
	if log.V(2) {
		log.Infof("post command packet=[% x]\n", buf)
	}
	return tun.Write(buf)
}

func NewSession(tun *Conn, cf *CipherFactory, identity string) *Session {
	sep := strings.IndexByte(identity, 0)
	var uid string
	if sep > 0 {
		uid = identity[:sep]
	} else {
		uid = identity
	}
	return &Session{tun, identity, uid, cf, make(map[string]bool)}
}

type CtlCommandHandler func(cmd byte, args []byte)
type CtlExitHandler func(addr string)

func RControlThread(tun *Conn, cmdHd CtlCommandHandler, exitHd CtlExitHandler) {
	defer ex.CatchException(recover())
	remoteAddr := tun.RemoteAddr().String()
	for {
		buf := make([]byte, 4)
		n, err := tun.Read(buf)
		if err != nil {
			log.Warningln("RControlThread exit caused by", err)
			break
		}
		if n == 4 {
			argslen := binary.BigEndian.Uint16(buf[2:])
			if argslen > 0 {
				argsbuf := make([]byte, argslen)
				n, err = tun.Read(argsbuf)
				go cmdHd(buf[0], argsbuf)
			} else {
				go cmdHd(buf[0], nil)
			}
		} else {
			log.Errorln("Abnormal command", buf, err)
			continue
		}
	}
	if exitHd != nil {
		exitHd(remoteAddr)
	}
}
