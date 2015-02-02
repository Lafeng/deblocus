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
	CTL_PING           = byte(1)
	CTL_PONG           = byte(2)
	TOKEN_REQUEST      = byte(5)
	TOKEN_REPLY        = byte(6)
	CTL_PING_INTERVAL  = time.Second * 60 // time.Minute
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

func (s *SessionMgr) clearTokens(session *Session) int {
	defer s.lock.Unlock()
	s.lock.Lock()
	var i = 0
	for k, _ := range session.tokens {
		delete(s.container, k)
		i++
	}
	return i
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
	defer func() { ex.CatchException(recover()) }()
	nego := &d5SNegotiation{Server: t}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fconn := NewConnWithHash(conn)
	session, err := nego.negotiate(fconn)
	if err == TRANS_SESSION {
		sid := atomic.AddInt32(&t.sid, 1)
		log.Infof("Serving SID#%X client=%s@%s\n", sid, session.uid, conn.RemoteAddr())
		fconn.SetSockOpt(-1, 0, 0)
		t.TransServe(fconn, session, nego.remnant, sid)
		return
	}
	if err != nil {
		log.Warningln("Close abnormal connection from ", conn.RemoteAddr(), err)
		SafeClose(conn)
		return
	}
	if session != nil {
		atomic.AddInt32(&t.aliveCT, 1)
		fconn.SetSockOpt(1, 1, 1)
		var ctl = NewCtlThread(session.tun, false)
		session.ctlThread = ctl
		var ser_cmdHandler CtlCommandHandler = func(cmd byte, args []byte) {
			switch cmd {
			case TOKEN_REQUEST:
				tokens := t.sessionMgr.createTokens(session, GENERATE_TOKEN_NUM)
				ctl.postCommand(TOKEN_REPLY, tokens)
			default:
				log.Warningf("Unrecognized command=%x packet=[% x]\n", cmd, args)
			}
		}
		var ser_exitHandler CtlExitHandler = func(addr string) {
			log.Warningf("CtlSession was disconnected %s\n", addr)
			var i = t.sessionMgr.clearTokens(session)
			if log.V(2) {
				log.Infof("Clear tokens %d of %s\n", i, addr)
			}
			session.tokens = nil
			SafeClose(session.tun)
			atomic.AddInt32(&t.aliveCT, -1)
		}
		ctl.start(ser_cmdHandler, ser_exitHandler)
	}
}

func (t *Server) TransServe(fconn *Conn, session *Session, remnant []byte, sid int32) {
	defer func() {
		SafeClose(fconn)
		ex.CatchException(recover())
		atomic.AddInt32(&t.aliveTT, -1)
	}()
	atomic.AddInt32(&t.aliveTT, 1)
	s5 := new(S5Target)
	var cipher = session.cipherFactory.NewCipher()
	cipher.decrypt(remnant, remnant)
	//dumpHex("remnant", remnant)
	remnant = remnant[SzTk:]
	target, err := s5.parseSocks5Target(remnant)
	if err != nil {
		log.Errorf("SID#%X Failed to connect to %s[%s] : [%s]\n", sid, s5.host, s5.dst, err)
	} else {
		fconn.cipher = cipher
		log.Infof("SID#%X %s[%s] is established\n", sid, s5.host, s5.dst)
		go Pipe(target, fconn, sid, session.ctlThread)
		Pipe(fconn, target, sid, session.ctlThread)
	}
}

func (t *Server) Stats() string {
	return fmt.Sprintf("Stats/Server CT=%d TT=%d TK=%d",
		atomic.LoadInt32(&t.aliveCT), atomic.LoadInt32(&t.aliveTT), t.sessionMgr.length())
}

type Session struct {
	tun           *Conn
	identity      string
	uid           string
	cipherFactory *CipherFactory
	tokens        map[string]bool
	ctlThread     *CtlThread
}

func NewSession(tun *Conn, cf *CipherFactory, identity string) *Session {
	sep := strings.IndexByte(identity, 0)
	var uid string
	if sep > 0 {
		uid = identity[:sep]
	} else {
		uid = identity
	}
	return &Session{tun, identity, uid, cf, make(map[string]bool), nil}
}

type CtlCommandHandler func(cmd byte, args []byte)
type CtlExitHandler func(addr string)

type CtlThread struct {
	tun           *Conn
	remoteAddr    string
	lived         *time.Timer
	lock          sync.Locker
	interval      time.Duration
	lastResetTime int64
}

func NewCtlThread(conn *Conn, isClient bool) *CtlThread {
	d := CTL_PING_INTERVAL
	if isClient {
		d *= 2
	}
	t := &CtlThread{
		tun:        conn,
		remoteAddr: conn.RemoteAddr().String(),
		lock:       new(sync.Mutex),
		interval:   d,
	}
	t.lived = time.AfterFunc(d, t.areYouAlive)
	return t
}

// all of the CtlCommandHandler and CtlExitHandler will be called in a new routine
func (t *CtlThread) start(cmdHd CtlCommandHandler, exitHd CtlExitHandler) {
	defer func() {
		ex.CatchException(recover())
		if t.lived != nil {
			// must clear timer
			t.lived.Stop()
		}
		if exitHd != nil {
			go exitHd(t.remoteAddr)
		}
	}()
	for {
		buf := make([]byte, 4)
		n, err := t.tun.Read(buf)
		if err != nil {
			log.Warningln("Exiting CtlThread caused by", err)
			break
		}
		if n == 4 {
			cmd := buf[0]
			argslen := binary.BigEndian.Uint16(buf[2:])
			if argslen > 0 {
				argsbuf := make([]byte, argslen)
				n, err = t.tun.Read(argsbuf)
				go cmdHd(cmd, argsbuf)
			} else {
				switch cmd {
				case CTL_PING: // reply
					go t.imAlive()
				case CTL_PONG: // aware of living
					go t.acknowledged()
				default:
					go cmdHd(cmd, nil)
				}
			}
		} else {
			log.Errorln("Abnormal command", buf, err)
			continue
		}
	}
}

func (t *CtlThread) postCommand(cmd byte, args []byte) (n int, err error) {
	t.lock.Lock()
	defer func() {
		t.tun.SetWriteDeadline(ZERO_TIME)
		t.lock.Unlock()
	}()
	buf := make([]byte, 4)
	buf[0] = cmd
	binary.BigEndian.PutUint16(buf[2:], uint16(len(args)))
	if args != nil {
		buf = append(buf, args...)
	}
	if log.V(4) {
		log.Infof("send command packet=[% x]\n", buf)
	}
	t.tun.SetWriteDeadline(time.Now().Add(CTL_PING_INTERVAL / 2))
	n, err = t.tun.Write(buf)
	return
}

func (t *CtlThread) active(times int64) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if times > 0 { // active link in transferring
		var d = (times - t.lastResetTime) << 1
		// allow reset at least half interval
		if d > int64(t.interval/time.Second) {
			if log.V(4) {
				log.Infoln("suppress the next ping task")
			}
			t.lastResetTime = times
			t.lived.Reset(t.interval)
		}
	} else if times < 0 { // scheduled ping
		t.interval = CTL_PING_INTERVAL * time.Duration(-times)
		t.lastResetTime = time.Now().Unix()
		t.lived.Reset(t.interval)
	}
}

func (t *CtlThread) areYouAlive() {
	if log.V(3) {
		log.Infoln("Ping/launched remote", t.remoteAddr)
	}
	_, err := t.postCommand(CTL_PING, nil)
	// Either waiting pong timeout or send ping failed
	if err != nil {
		SafeClose(t.tun)
		log.Warningln("Ping remote failed and then closed", t.tun.RemoteAddr(), err)
	} else {
		t.tun.SetReadDeadline(time.Now().Add(CTL_PING_INTERVAL / 2))
		// impossible call by timer, will reset by acknowledged or read timeout.
		t.active(-1)
	}
}

func (t *CtlThread) acknowledged() {
	if log.V(3) {
		log.Infoln("Ping/acknowledged", t.remoteAddr)
	}
	t.tun.SetReadDeadline(ZERO_TIME)
	t.active(-2) // so slow down the tempo
}

func (t *CtlThread) imAlive() {
	if log.V(3) {
		log.Infoln("Ping/responded", t.remoteAddr)
	}
	t.active(-1) // up tempo for become a sender
	_, err := t.postCommand(CTL_PONG, nil)
	if err != nil {
		SafeClose(t.tun)
		log.Warningln("Reply ping failed and then closed", t.tun.RemoteAddr(), err)
	}
}
