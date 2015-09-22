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

// read by the first segment indicated the following segment length
// len_inByte: first segment length in byte
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

// socks5 protocol step1 on client side
type S5Step1 struct {
	conn   net.Conn
	err    error
	target []byte
}

func (s *S5Step1) Handshake() {
	var buf = make([]byte, 2)
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
	n, err := io.ReadAtLeast(s.conn, buf, nmethods)
	if err != nil || n != nmethods {
		s.err = INVALID_SOCKS5_HEADER
		log.Warningln("invalid socks5 header:", hex.EncodeToString(buf))
	}
}

func (s *S5Step1) HandshakeAck() bool {
	msg := []byte{5, 0}
	if s.err != nil {
		// handshake error feedback
		log.Errorln(s.err)
		if ex, y := s.err.(*exception.Exception); y {
			msg[1] = byte(ex.Code())
		} else {
			msg[1] = 0xff
		}
		s.conn.Write(msg)
		s.conn.Close()
		return true
	}
	// accept
	_, err := s.conn.Write(msg)
	if err != nil {
		log.Errorln(err)
		s.conn.Close()
		return true
	}
	return false
}

func (s *S5Step1) parseSocks5Request() string {
	var buf = make([]byte, 262) // 4+(1+255)+2
	_, err := s.conn.Read(buf)
	ThrowErr(err)
	ver, cmd, atyp := buf[0], buf[1], buf[3]
	if ver != SOCKS5_VER || cmd != 1 {
		s.err = INVALID_SOCKS5_REQUEST
		return NULL
	}
	s.target = buf[3:]
	buf = buf[4:]
	var host string
	var ofs int
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

func (s *S5Step1) respondSocks5() bool {
	var ack = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if s.err != nil {
		// handshake error feedback
		if ex, y := s.err.(*exception.Exception); y {
			ack[1] = byte(ex.Code())
		} else {
			ack[1] = 0x1
		}
		s.conn.Write(ack)
		s.conn.Close()
		return true
	}
	// accept
	_, err := s.conn.Write(ack)
	if err != nil {
		log.Infoln(err)
		return true
	}
	return false
}

// http proxy

func detectProtocol(pbconn *pushbackInputStream) int {
	var b = make([]byte, 2)
	n, e := io.ReadFull(pbconn, b)
	if n != 2 {
		panic(io.ErrUnexpectedEOF.Error())
	}
	if e != nil {
		panic(e.Error())
	}
	defer pbconn.Unread(b)
	var head = b[0]
	// hex 0x41-0x5a=A-Z 0x61-0x7a=a-z
	if head <= 5 {
		return REQ_PROT_SOCKS5
	} else if head >= 0x41 && head <= 0x7a {
		return REQ_PROT_HTTP
	} else {
		return REQ_PROT_UNKNOWN
	}
}

func httpProxyHandshake(conn *pushbackInputStream) (req_prot uint, target string) {
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		panic(err)
	}
	// http tunnel, direct into tunnel
	if req.Method == "CONNECT" { // respond OK then enter into tunnel
		req_prot = REQ_PROT_HTTP_T
		conn.WriteString(HTTP_PROXY_VER_LINE)
		conn.WriteString(CRLF)
		conn.WriteString(HTTP_PROXY_AGENT + "/" + VER_STRING)
		conn.WriteString(CRLF + CRLF)
		target = req.Host
	} else { // plain http request
		req_prot = REQ_PROT_HTTP
		for k, _ := range req.Header {
			if strings.HasPrefix(k, "Proxy") {
				delete(req.Header, k)
			}
		}
		buf := new(bytes.Buffer)
		req.Write(buf)
		conn.Unread(buf.Bytes())
		target = req.Host
	}
	if target == NULL {
		panic("missing host in address")
	}
	_, _, err = net.SplitHostPort(target)
	if err != nil {
		// the header.Host without port
		if strings.Contains(err.Error(), "port") && req.Method != "CONNECT" {
			target += ":80"
		} else {
			panic(err.Error())
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
type d5CNegotiation struct {
	*D5Params
	dhKeys   *DHKeyPair
	identity string
}

func (nego *d5CNegotiation) negotiate(p *tunParams) (conn *Conn, err error) {
	var con *net.TCPConn
	defer func() {
		if e, y := exception.ErrorOf(recover()); y {
			SafeClose(con)
			err = e
		}
	}()
	con, err = net.DialTCP("tcp", nil, nego.d5sAddr)
	ThrowIf(err != nil, D5SER_UNREACHABLE)
	setSoTimeout(con)
	var hConn = NewConnWithHash(con)
	conn = hConn.Conn
	nego.requestAuthAndDHExchange(hConn)
	setSoTimeout(con)
	p.cipherFactory = nego.finishDHExThenSetupCipher(hConn)
	hConn.cipher = p.cipherFactory.NewCipher(nil)
	setSoTimeout(con)
	nego.validateAndGetTokens(hConn, p)
	return
}

// send
// obf~256 | idBlockLen~2 | idBlock(enc)~? | dhPubLen~2 | dhPub~?
func (nego *d5CNegotiation) requestAuthAndDHExchange(conn *hashedConn) {
	// obfuscated header 256
	obf := randArray(256, 256)
	obf[0xff] = d5Sub(obf[0xd5])
	// send identity using rsa
	identity := nego.user + IDENTITY_SEP + nego.pass
	idBlock, err := RSAEncrypt([]byte(identity), nego.sPub)
	ThrowErr(err)
	buf := new(bytes.Buffer)
	buf.Write(obf)
	idBlockLen := uint16(len(idBlock))
	binary.BigEndian.PutUint16(obf, idBlockLen)
	buf.Write(obf[:2])
	buf.Write(idBlock)
	buf.Write(nego.dhKeys.pubLen)
	buf.Write(nego.dhKeys.pub)
	_, err = conn.Write(buf.Bytes())
	ThrowErr(err)
}

// recv: rhPub~2+256
func (nego *d5CNegotiation) finishDHExThenSetupCipher(conn *hashedConn) *CipherFactory {
	buf, err := ReadFullByLen(2, conn)
	ThrowErr(err)
	if len(buf) == 1 {
		switch buf[0] {
		case 0xff:
			err = auth.AUTH_FAILED
		default:
			err = VALIDATION_FAILED.Apply("indentity")
		}
		ThrowErr(err)
	}
	secret := takeSharedKey(nego.dhKeys, buf)
	return NewCipherFactory(nego.cipher, secret)
}

func (nego *d5CNegotiation) validateAndGetTokens(sconn *hashedConn, t *tunParams) {
	buf, err := ReadFullByLen(2, sconn)
	ThrowErr(err)
	tVer := VERSION
	oVer := binary.BigEndian.Uint32(buf)
	if oVer > tVer {
		oVerStr := fmt.Sprintf("%d.%d.%04d", oVer>>24, (oVer>>16)&0xFF, oVer&0xFFFF)
		tVer >>= 16
		oVer >>= 16
		if tVer == oVer {
			log.Warningf("Caution !!! Please upgrade to new version, remote is v%s\n", oVerStr)
		} else {
			err = INCOMPATIBLE_VERSION.Apply(oVerStr)
		}
		ThrowErr(err)
	}
	ofs := 4
	ofs += 2
	t.dtInterval = int(binary.BigEndian.Uint16(buf[ofs:]))
	ofs += 2
	t.tunQty = int(buf[ofs])
	t.token = buf[TUN_PARAMS_LEN:]
	if log.V(3) {
		n := len(buf) - TUN_PARAMS_LEN
		log.Infof("Received tokens count=%d\n", n/TKSZ)
	}
	rHash := sconn.RHashSum()
	wHash := sconn.WHashSum()
	_, err = sconn.Write(rHash)
	ThrowErr(err)
	oHash := make([]byte, TKSZ)
	_, err = sconn.Read(oHash)
	if !bytes.Equal(wHash, oHash) {
		log.Errorln("Server hash/r is inconsistence with the client/w")
		log.Errorf("rHash: [% x] wHash: [% x]\n", rHash, wHash)
		log.Errorf("oHash: [% x]\n", oHash)
		ThrowErr(INCONSISTENT_HASH)
	}
}

//
// d5Server negotiation
//
type d5SNegotiation struct {
	*Server
	clientAddr     string
	clientIdentity string
	tokenBuf       []byte
}

func (nego *d5SNegotiation) negotiate(hConn *hashedConn) (session *Session, err error) {
	setSoTimeout(hConn)
	nego.clientAddr = hConn.RemoteAddr().String()
	var (
		nr  int
		buf = make([]byte, DMLEN1)
	)
	nr, err = hConn.Read(buf)
	if err != nil {
		return nil, err
	}

	if nr == DMLEN2 &&
		d5SumValid(buf[TKSZ-2], buf[TKSZ]) && d5SumValid(buf[TKSZ-1], buf[TKSZ+1]) {
		return nego.dataSession(hConn, buf)
	}
	if nr == DMLEN1 &&
		d5SumValid(buf[0xd5], buf[0xff]) {
		return nego.handshakeSession(hConn)
	}
	log.Warningf("Unrecognized Request from=%s len=%d\n", nego.clientAddr, nr)
	return nil, NEGOTIATION_FAILED
}

func (nego *d5SNegotiation) handshakeSession(hConn *hashedConn) (session *Session, err error) {
	defer func() {
		if e, y := exception.ErrorOf(recover()); y {
			err = e
		}
	}()
	setSoTimeout(hConn)
	var skey = nego.verifyThenDHExchange(hConn)
	var cf = NewCipherFactory(nego.Cipher, skey)
	hConn.cipher = cf.NewCipher(nil)
	session = NewSession(hConn.Conn, cf, nego)
	setSoTimeout(hConn)
	nego.respondTestWithToken(hConn, session)
	return
}

func (nego *d5SNegotiation) dataSession(hConn *hashedConn, buf []byte) (session *Session, err error) {
	token := buf[:TKSZ]
	if session := nego.sessionMgr.take(token); session != nil {
		session.identifyConn(hConn.Conn)
		nego.tokenBuf = buf
		return session, DATATUN_SESSION
	}
	log.Warningln("Incorrect token from", hConn.RemoteAddr())
	return nil, VALIDATION_FAILED
}

func (nego *d5SNegotiation) verifyThenDHExchange(conn net.Conn) (key []byte) {
	credBuf, err := ReadFullByLen(2, conn)
	ThrowIf(err != nil, err)
	userIdentity, err := RSADecrypt(credBuf, nego.RSAKeys.priv)
	ThrowErr(err)
	clientIdentity := string(userIdentity)
	if log.V(2) {
		log.Infoln("Auth clientIdentity:", SubstringBefore(clientIdentity, IDENTITY_SEP), "***")
	}
	allow, ex := nego.AuthSys.Authenticate(userIdentity)
	cDHPub, err := ReadFullByLen(2, conn)
	if !allow { // invalid user indentity
		log.Warningf("Auth %s failed: %v\n", clientIdentity, ex)
		conn.Write([]byte{0, 1, 0xff})
		panic(ex)
	}
	nego.clientIdentity = clientIdentity
	key = takeSharedKey(nego.dhKeys, cDHPub)
	//	if log.V(5) {
	//		dumpHex("Sharedkey", key)
	//	}
	buf := new(bytes.Buffer)
	buf.Write(nego.dhKeys.pubLen)
	buf.Write(nego.dhKeys.pub)
	_, err = buf.WriteTo(conn)
	return
}

//         |------------- tun params ------------|
// | len~2 | version~4 | interval~2 | reserved~? | tokens~20N ; hash~20
func (nego *d5SNegotiation) respondTestWithToken(sconn *hashedConn, session *Session) {
	var (
		headLen = TUN_PARAMS_LEN + 2
		err     error
	)
	// tun params
	tpBuf := randArray(headLen, headLen)
	binary.BigEndian.PutUint16(tpBuf, uint16(TUN_PARAMS_LEN+GENERATE_TOKEN_NUM*TKSZ))
	ofs := 2
	copy(tpBuf[ofs:], ito4b(VERSION))
	ofs += 4
	binary.BigEndian.PutUint16(tpBuf[ofs:], uint16(0))
	ofs += 2
	binary.BigEndian.PutUint16(tpBuf[ofs:], uint16(DT_PING_INTERVAL))
	ofs += 2
	tpBuf[ofs] = PARALLEL_TUN_QTY

	_, err = sconn.Write(tpBuf)
	ThrowErr(err)
	tokens := nego.sessionMgr.createTokens(session, GENERATE_TOKEN_NUM)
	_, err = sconn.Write(tokens[1:])
	ThrowErr(err)
	rHash := sconn.RHashSum()
	wHash := sconn.WHashSum()
	oHash := make([]byte, TKSZ)
	_, err = sconn.Read(oHash)
	ThrowErr(err)
	if !bytes.Equal(wHash, oHash) {
		log.Errorln("Remote hash/r not equals self/w")
		log.Errorf("rHash: [% x] wHash: [% x]\n", rHash, wHash)
		log.Errorf("oHash: [% x]\n", oHash)
		panic(INCONSISTENT_HASH)
	}
	_, err = sconn.Write(rHash)
	ThrowErr(err)
}
