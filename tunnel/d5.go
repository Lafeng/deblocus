package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/Lafeng/deblocus/auth"
	"github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/golang/glog"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	D5                 = 0xd5
	IPV4               = byte(1)
	DOMAIN             = byte(3)
	IPV6               = byte(4)
	SOCKS5_VER         = byte(5)
	NULL               = ""
	DMLEN1             = 256
	DMLEN2             = TKSZ + 2
	GENERAL_SO_TIMEOUT = 10 * time.Second
	TUN_PARAMS_LEN     = 32

	REQ_PROT_UNKNOWN    = 1
	REQ_PROT_SOCKS5     = 2
	REQ_PROT_HTTP       = 3
	REQ_PROT_HTTP_T     = 4
	IDENTITY_SEP        = "\x00"
	CRLF                = "\r\n"
	HTTP_PROXY_VER_LINE = "HTTP/1.1 200 Connection established"
	HTTP_PROXY_AGENT    = "Proxy-Agent: "
)

var (
	// for main package injection
	VERSION    uint32
	VER_STRING string
	DEBUG      bool
)

var (
	// socks5 exceptions
	INVALID_SOCKS5_HEADER  = exception.New(0xff, "Invalid socks5 header")
	INVALID_SOCKS5_REQUEST = exception.New(0x07, "Invalid socks5 request")
	GENERAL_FAILURE        = exception.New(0x01, "General failure")
	HOST_UNREACHABLE       = exception.New(0x04, "Host is unreachable")
)

var (
	// D5 exceptions
	INVALID_D5PARAMS     = exception.NewW("Invalid D5Params")
	D5SER_UNREACHABLE    = exception.NewW("D5Server is unreachable")
	VALIDATION_FAILED    = exception.NewW("Validation failed")
	NEGOTIATION_FAILED   = exception.NewW("Negotiation failed")
	DATATUN_SESSION      = exception.NewW("DT")
	INCONSISTENT_HASH    = exception.NewW("Inconsistent hash")
	INCOMPATIBLE_VERSION = exception.NewW("Incompatible version")
)

// len_inByte: first segment length of bytes, enum: 1,2,4
func ReadFullByLen(len_inByte int, reader io.Reader) (buf []byte, err error) {
	lb := make([]byte, len_inByte)
	_, err = io.ReadFull(reader, lb)
	if err != nil {
		return
	}
	switch len_inByte {
	case 1:
		buf = make([]byte, lb[0])
	case 2:
		buf = make([]byte, binary.BigEndian.Uint16(lb))
	case 4:
		buf = make([]byte, binary.BigEndian.Uint32(lb))
	}
	_, err = io.ReadFull(reader, buf)
	return
}

// socks5 protocol handler on client side
type s5Handler struct {
	conn net.Conn
	err  error
}

// step1
func (s *s5Handler) handshake() {
	var buf = make([]byte, 2)
	setRTimeout(s.conn)
	_, err := io.ReadFull(s.conn, buf)
	if err != nil {
		s.err = INVALID_SOCKS5_HEADER.Apply(err)
		return
	}

	ver, nmethods := buf[0], int(buf[1])
	if ver != SOCKS5_VER || nmethods < 1 {
		s.err = INVALID_SOCKS5_HEADER.Apply(fmt.Sprintf("[% x]", buf[:2]))
		return
	}

	buf = make([]byte, nmethods+1) // consider method non-00
	setRTimeout(s.conn)
	n, err := io.ReadAtLeast(s.conn, buf, nmethods)
	if err != nil || n != nmethods {
		s.err = INVALID_SOCKS5_HEADER
		log.Warningln("invalid socks5 header:", hex.EncodeToString(buf))
	}
}

// step1 response
// return: True=Denied
func (s *s5Handler) handshakeResponse() bool {
	msg := []byte{5, 0}
	if s.err != nil {
		// handshake error feedback
		log.Warningln(s.err)
		if ex, y := s.err.(*exception.Exception); y {
			msg[1] = byte(ex.Code())
		} else {
			msg[1] = 0xff
		}
		setWTimeout(s.conn)
		s.conn.Write(msg)
		return true
	}

	// accept
	setWTimeout(s.conn)
	_, err := s.conn.Write(msg)
	if err != nil {
		log.Warningln(err)
		return true
	}
	return false
}

// step2
func (s *s5Handler) parseRequest() string {
	var (
		buf  = make([]byte, 262) // 4+(1+255)+2
		host string
		ofs  int
	)

	setRTimeout(s.conn)
	_, err := s.conn.Read(buf)
	ThrowErr(err)
	ver, cmd, atyp := buf[0], buf[1], buf[3]
	if ver != SOCKS5_VER || cmd != 1 {
		s.err = INVALID_SOCKS5_REQUEST
		return NULL
	}

	buf = buf[4:]
	switch atyp {
	case IPV4:
		host = net.IP(buf[:net.IPv4len]).String()
		ofs = net.IPv4len
	case IPV6:
		host = "[" + net.IP(buf[:net.IPv6len]).String() + "]"
		ofs = net.IPv6len
	case DOMAIN:
		dlen := int(buf[0])
		host = string(buf[1 : dlen+1])
		ofs = dlen + 1
	default:
		s.err = INVALID_SOCKS5_REQUEST
		return NULL
	}
	var dst_port = binary.BigEndian.Uint16(buf[ofs : ofs+2])
	return host + ":" + strconv.Itoa(int(dst_port))
}

// step2 response
// return True=Denied
func (s *s5Handler) finalResponse() bool {
	var msg = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if s.err != nil {
		// handshake error feedback
		if ex, y := s.err.(*exception.Exception); y {
			msg[1] = byte(ex.Code())
		} else {
			msg[1] = 0x1
		}
		setWTimeout(s.conn)
		s.conn.Write(msg)
		return true
	}
	// accept
	setWTimeout(s.conn)
	_, err := s.conn.Write(msg)
	if err != nil {
		log.Warningln(err)
		return true
	}
	return false
}

// http proxy

func detectProtocol(pbconn *pushbackInputStream) (int, error) {
	var b = make([]byte, 2)
	setRTimeout(pbconn)
	n, e := io.ReadFull(pbconn, b)
	if n != 2 {
		return 0, io.ErrUnexpectedEOF
	}
	if e != nil {
		return 0, e
	}

	defer pbconn.Unread(b)
	var head = b[0]

	if head <= 5 {
		return REQ_PROT_SOCKS5, nil
		// hex 0x41-0x5a=A-Z 0x61-0x7a=a-z
	} else if head >= 0x41 && head <= 0x7a {
		return REQ_PROT_HTTP, nil
	} else {
		return REQ_PROT_UNKNOWN, nil
	}
}

// throw errors
func httpProxyHandshake(conn *pushbackInputStream) (proto uint, target string) {
	reader := bufio.NewReader(conn)
	setRTimeout(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)

	// http tunnel, direct into tunnel
	if req.Method == "CONNECT" {
		proto = REQ_PROT_HTTP_T
		target = req.Host

		// response http header
		buf.WriteString(HTTP_PROXY_VER_LINE)
		buf.WriteString(CRLF)
		buf.WriteString(HTTP_PROXY_AGENT + "/" + VER_STRING)
		buf.WriteString(CRLF + CRLF)
		setWTimeout(conn)
		conn.Write(buf.Bytes())

	} else { // plain http request
		proto = REQ_PROT_HTTP
		target = req.Host

		// delete http header Proxy-xxx
		for k, _ := range req.Header {
			if strings.HasPrefix(k, "Proxy") {
				delete(req.Header, k)
			}
		}
		// serialize modified request to buffer
		req.Write(buf)
		// rollback
		conn.Unread(buf.Bytes())
	}

	if target == NULL {
		panic("missing host in address")
	}

	_, _, err = net.SplitHostPort(target)
	if err != nil {
		// plain http request: the header.Host without port
		if strings.Contains(err.Error(), "port") && req.Method != "CONNECT" {
			target += ":80"
		} else {
			panic(err)
		}
	}
	return
}

func d5Sub(a byte) byte {
	return byte(D5 - int(int8(a)))
}

func d5SumValid(a, b byte) bool {
	return uint(int8(a)+int8(b))&0xff == D5
}

type tunParams struct {
	cipherFactory *CipherFactory
	token         []byte
	dtInterval    int
	tunQty        int
}

//
// client negotiation
//
type dbcCltNego struct {
	*D5Params
	dhKey DHKE
}

func (n *dbcCltNego) negotiate(p *tunParams) (conn *Conn, err error) {
	var rawConn net.Conn
	defer func() {
		if e, y := exception.ErrorOf(recover()); y {
			SafeClose(rawConn)
			err = e
		}
	}()
	rawConn, err = net.DialTimeout("tcp", n.d5sAddrStr, GENERAL_SO_TIMEOUT)
	ThrowIf(err != nil, D5SER_UNREACHABLE)

	hConn := newHashedConn(rawConn)
	conn = hConn.Conn
	n.requestAuthAndDHExchange(hConn)

	p.cipherFactory = n.finishDHExThenSetupCipher(hConn)
	hConn.cipher = p.cipherFactory.InitCipher(nil)

	n.validateAndGetTokens(hConn, p)
	return
}

// send
// obf~256 | idBlockLen~2 | idBlock(enc)~? | dhPubLen~2 | dhPub~?
func (n *dbcCltNego) requestAuthAndDHExchange(conn *hashedConn) {
	// obfuscated header 256
	obf := randArray(256, 256)
	obf[0xff] = d5Sub(obf[0xd5])
	buf := new(bytes.Buffer)
	buf.Write(obf)

	// send identity using rsa
	identity := n.user + IDENTITY_SEP + n.pass
	idBlock, err := RSAEncrypt([]byte(identity), n.sPub)
	ThrowErr(err)

	// idBlock
	idBlockLen := uint16(len(idBlock))
	binary.BigEndian.PutUint16(obf, idBlockLen)
	buf.Write(obf[:2])
	buf.Write(idBlock)

	// dhke
	pub := n.dhKey.ExportPubKey()
	binary.BigEndian.PutUint16(obf, uint16(len(pub)))
	buf.Write(obf[:2])
	buf.Write(pub)

	setWTimeout(conn)
	_, err = conn.Write(buf.Bytes())
	ThrowErr(err)
}

func (n *dbcCltNego) finishDHExThenSetupCipher(conn *hashedConn) *CipherFactory {
	// recv: rhPub~2+256 or ecdhPub~2+32
	setRTimeout(conn)
	buf, err := ReadFullByLen(2, conn)
	ThrowErr(err)

	if len(buf) == 1 {
		switch buf[0] {
		case 0xff: // invalid indentity
			err = auth.AUTH_FAILED
		default:
			ThrowErr(VALIDATION_FAILED.Apply("indentity"))
		}
	}

	key, err := n.dhKey.ComputeKey(buf)
	ThrowErr(err)
	return NewCipherFactory(n.cipher, key)
}

func (n *dbcCltNego) validateAndGetTokens(hConn *hashedConn, t *tunParams) {
	setRTimeout(hConn)
	buf, err := ReadFullByLen(2, hConn)
	ThrowErr(err)

	myVer := VERSION
	rVer := binary.BigEndian.Uint32(buf)
	if rVer > myVer {
		rVerStr := fmt.Sprintf("%d.%d.%04d", rVer>>24, (rVer>>16)&0xFF, rVer&0xFFFF)
		myVer >>= 16
		rVer >>= 16
		if myVer == rVer {
			log.Warningf("Caution !!! Please upgrade to new version, remote is v%s\n", rVerStr)
		} else {
			ThrowErr(INCOMPATIBLE_VERSION.Apply(rVerStr))
			// return
		}
	}
	// parse params
	ofs := 4 // skiped upon version
	t.dtInterval = int(binary.BigEndian.Uint16(buf[ofs:]))
	ofs += 2
	t.tunQty = int(buf[ofs])
	t.token = buf[TUN_PARAMS_LEN:] // absolute offset

	if log.V(3) {
		n := len(buf) - TUN_PARAMS_LEN
		log.Infof("Received tokens size=%d\n", n/TKSZ)
	}

	// send rHash
	rHash := hConn.RHashSum()
	wHash := hConn.WHashSum()
	setWTimeout(hConn)
	_, err = hConn.Write(rHash)
	ThrowErr(err)

	// recv remote rHash
	oHash := make([]byte, TKSZ)
	setRTimeout(hConn)
	_, err = hConn.Read(oHash)
	ThrowErr(err)

	if !bytes.Equal(wHash, oHash) {
		log.Errorln("Server hash-r is inconsistence with myself-w")
		log.Errorf("my WHash: [% x]\n", wHash)
		log.Errorf("peer RHash: [% x]\n", oHash)
		ThrowErr(INCONSISTENT_HASH)
	}
}

//
// Server negotiation
//
type dbcSerNego struct {
	*Server
	clientAddr     string
	clientIdentity string
	isNewSession   bool
}

func (n *dbcSerNego) negotiate(hConn *hashedConn) (session *Session, err error) {
	n.clientAddr = hConn.RemoteAddr().String()
	var (
		nr  int
		buf = make([]byte, DMLEN1)
	)

	setRTimeout(hConn)
	nr, err = hConn.Read(buf)
	if err != nil {
		return nil, err
	}

	if nr == DMLEN2 &&
		d5SumValid(buf[TKSZ-2], buf[TKSZ]) && d5SumValid(buf[TKSZ-1], buf[TKSZ+1]) {
		return n.dataSession(hConn, buf)
	}

	if nr == DMLEN1 &&
		d5SumValid(buf[0xd5], buf[0xff]) {
		return n.handshakeSession(hConn)
	}

	log.Warningf("Unrecognized Request from=%s len=%d\n", n.clientAddr, nr)
	return nil, NEGOTIATION_FAILED
}

// new connection
func (n *dbcSerNego) handshakeSession(hConn *hashedConn) (session *Session, err error) {
	defer func() {
		if e, y := exception.ErrorOf(recover()); y {
			err = e
		}
	}()
	var skey = n.verifyThenDHExchange(hConn)
	var cf = NewCipherFactory(n.Cipher, skey)

	hConn.cipher = cf.InitCipher(nil)
	session = NewSession(hConn.Conn, cf, n)
	n.isNewSession = true
	n.respondTestWithToken(hConn, session)
	return
}

// quick resume session
func (n *dbcSerNego) dataSession(hConn *hashedConn, buf []byte) (session *Session, err error) {
	token := buf[:TKSZ]
	if session := n.sessionMgr.take(token); session != nil {
		// init cipher of new connection
		hConn.cipher = session.cipherFactory.InitCipher(token)
		// check and set identify
		session.identifyConn(hConn.Conn)
		return session, nil
	}

	log.Warningln("Incorrect token from", n.clientAddr)
	return nil, VALIDATION_FAILED
}

func (n *dbcSerNego) verifyThenDHExchange(conn net.Conn) (key []byte) {
	// client identity segment
	setRTimeout(conn)
	credBuf, err := ReadFullByLen(2, conn)
	ThrowErr(err)

	identityRaw, err := RSADecrypt(credBuf, n.RSAKeys.priv)
	ThrowErr(err)

	identityStr := string(identityRaw)
	if log.V(2) {
		log.Infoln("Auth clientIdentity:", SubstringBefore(identityStr, IDENTITY_SEP), "***")
	}

	allow, err := n.AuthSys.Authenticate(identityRaw)
	if allow {
		n.clientIdentity = identityStr
	} else { // client denied
		log.Warningf("Auth %s failed: %v\n", identityStr, err)
		// reply failed msg
		conn.Write([]byte{0, 1, 0xff})
		panic(err)
	}

	// read client RH-pub
	setRTimeout(conn)
	bobPub, err := ReadFullByLen(2, conn)
	ThrowErr(err)
	key, err = n.dhKey.ComputeKey(bobPub)
	ThrowErr(err)

	// send my RH-pub
	myPub := n.dhKey.ExportPubKey()
	buf := make([]byte, len(myPub)+2)
	binary.BigEndian.PutUint16(buf, uint16(len(myPub)))
	copy(buf[2:], myPub)

	setWTimeout(conn)
	_, err = conn.Write(buf)
	ThrowErr(err)
	return
}

//         |------------- tun params ------------|
// | len~2 | version~4 | interval~2 | reserved~? | tokens~20N ; hash~20
func (n *dbcSerNego) respondTestWithToken(hConn *hashedConn, session *Session) {
	var (
		headLen  = TUN_PARAMS_LEN + 2
		totalLen = TUN_PARAMS_LEN + GENERATE_TOKEN_NUM*TKSZ
		err      error
	)
	// tun params buffer built from rand
	tpBuf := randArray(headLen, headLen)
	// len
	binary.BigEndian.PutUint16(tpBuf, uint16(totalLen))
	ofs := 2

	// ver
	copy(tpBuf[ofs:], ito4b(VERSION))
	ofs += 4

	// params
	// ping interval
	binary.BigEndian.PutUint16(tpBuf[ofs:], uint16(DT_PING_INTERVAL))
	ofs += 2

	// tun qty
	tpBuf[ofs] = PARALLEL_TUN_QTY

	setWTimeout(hConn)
	_, err = hConn.Write(tpBuf) // just header
	ThrowErr(err)

	// send tokens
	tokens := n.sessionMgr.createTokens(session, GENERATE_TOKEN_NUM)
	setWTimeout(hConn)
	_, err = hConn.Write(tokens[1:]) // skip index=0
	ThrowErr(err)

	rHash := hConn.RHashSum()
	wHash := hConn.WHashSum()
	oHash := make([]byte, TKSZ)
	setRTimeout(hConn)
	_, err = hConn.Read(oHash)
	ThrowErr(err)

	if !bytes.Equal(wHash, oHash) {
		log.Errorln("Client hash-r is inconsistence with myself-w")
		log.Errorf("my WHash: [% x]\n", wHash)
		log.Errorf("peer RHash: [% x]\n", oHash)
		panic(INCONSISTENT_HASH)
	}

	setWTimeout(hConn)
	_, err = hConn.Write(rHash)
	ThrowErr(err)
}
