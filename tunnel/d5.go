package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/Lafeng/deblocus/auth"
	"github.com/Lafeng/deblocus/crypto"
	"github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/golang/glog"
	"github.com/dchest/siphash"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	IPV4        byte = 1
	DOMAIN      byte = 3
	IPV6        byte = 4
	S5_VER      byte = 5
	AUTH_FAILED byte = 0xff
	TYPE_NEW    byte = 0xfb
	TYPE_DAT    byte = 0xf1
)

const (
	GENERAL_SO_TIMEOUT = 10 * time.Second
	TUN_PARAMS_LEN     = 32

	DP_LEN1    = 256
	DP_P2I     = 256 + 8
	DP_MOD     = 65536
	TIME_STEP  = 60 // seconds
	TIME_ERROR = 1  // minutes

	REQ_PROT_UNKNOWN    = 1
	REQ_PROT_SOCKS5     = 2
	REQ_PROT_HTTP       = 3
	REQ_PROT_HTTP_T     = 4
	NULL                = ""
	CRLF                = "\r\n"
	IDENTITY_SEP        = "\x00"
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
	UNRECOGNIZED_REQ     = exception.NewW("Unrecognized Request")
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
	if ver != S5_VER || nmethods < 1 {
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
	if ver != S5_VER || cmd != 1 {
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

type tunParams struct {
	cipherFactory *CipherFactory
	token         []byte
	pingInterval  int
	parallels     int
}

// write to buf
// for server
func (p *tunParams) serialize(buf []byte) (offset int) {
	binary.BigEndian.PutUint16(buf, uint16(p.pingInterval))
	offset = 2

	buf[offset] = byte(p.parallels)
	offset++
	return
}

// read from raw buf
// for client
func (p *tunParams) deserialize(buf []byte, offset int) {
	p.pingInterval = int(binary.BigEndian.Uint16(buf[offset:]))
	offset += 2

	p.parallels = int(buf[offset])
	//offset++

	// absolute offset
	p.token = buf[TUN_PARAMS_LEN:]
	return
}

//
// client negotiation
//
type dbcCltNego struct {
	*D5Params
	dhKey  crypto.DHKE
	ibHash []byte
}

func (n *dbcCltNego) negotiate(p *tunParams) (conn *Conn, err error) {
	var rawConn net.Conn
	defer func() {
		// free ibHash
		n.ibHash = nil
		if e, y := exception.ErrorOf(recover()); y {
			SafeClose(rawConn)
			err = e
		}
	}()
	rawConn, err = net.DialTimeout("tcp", n.d5sAddrStr, GENERAL_SO_TIMEOUT)
	ThrowIf(err != nil, D5SER_UNREACHABLE)

	var hConn *hashedConn
	hConn, conn = newHashedConn(rawConn)
	n.requestAuthAndDHExchange(hConn)

	p.cipherFactory = n.finishDHExThenSetupCipher(hConn)
	hConn.cipher = p.cipherFactory.InitCipher(nil)

	n.validateAndGetTokens(hConn, p)
	return
}

// send
// obf~256 | idBlockLen~2 | idBlock(enc)~? | dhPubLen~2 | dhPub~?
func (n *dbcCltNego) requestAuthAndDHExchange(conn *hashedConn) {
	// obfuscated header
	obf := makeDbcHead(TYPE_NEW, n.rsaKey.SharedKey())
	buf := new(bytes.Buffer)
	buf.Write(obf)

	// send identity using rsa
	idBlock, err := n.idBlockSerialize()
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

	if len(buf) == 1 { // failed
		switch buf[0] {
		case AUTH_FAILED:
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

	// compare version with remote
	myVer := VERSION
	rVer := binary.BigEndian.Uint32(buf)
	ofs := 4
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

	// check ibHash
	_ibHash := buf[ofs : ofs+20]
	ofs += 20
	if !bytes.Equal(n.ibHash, _ibHash) {
		// S->C is polluted.
		ThrowErr(INCONSISTENT_HASH.Apply("MitM attack"))
	}

	// parse params
	t.deserialize(buf, ofs)

	if log.V(3) {
		log.Infof("Received tokens size=%d\n", len(t.token)/TKSZ)
	}

	// validated or throws
	verifyHash(hConn, false)
}

func verifyHash(hConn *hashedConn, isServ bool) {
	hashBuf := make([]byte, hConn.hashSize*2)
	rHash, wHash := hConn.HashSum()
	var err error

	if !isServ { // client send hash at first
		copy(hashBuf[:hConn.hashSize], rHash)
		copy(hashBuf[hConn.hashSize:], wHash)
		setWTimeout(hConn)
		_, err = hConn.Write(hashBuf)
		ThrowErr(err)
	}

	setRTimeout(hConn)
	_, err = io.ReadFull(hConn, hashBuf)
	ThrowErr(err)

	rHashp, wHashp := hashBuf[:hConn.hashSize], hashBuf[hConn.hashSize:]
	if !bytes.Equal(rHash, wHashp) || !bytes.Equal(wHash, rHashp) {
		log.Errorln("My hash is inconsistent with peer")
		if DEBUG {
			log.Errorf("  My Hash r:[% x] w:[% x]", rHash, wHash)
			log.Errorf("Peer Hash r:[% x] w:[% x]", rHashp, wHashp)
		}
		ThrowErr(INCONSISTENT_HASH)
	}

	if isServ { // server reply hash
		copy(hashBuf[:hConn.hashSize], rHash)
		copy(hashBuf[hConn.hashSize:], wHash)
		setWTimeout(hConn)
		_, err = hConn.Write(hashBuf)
		ThrowErr(err)
	}
}

//
// Server negotiation
//
type dbcSerNego struct {
	*Server
	clientAddr     net.Addr
	clientIdentity string
	isNewSession   bool
	ibHash         []byte
}

func (n *dbcSerNego) negotiate(hConn *hashedConn, tcPool []uint64) (session *Session, err error) {
	var (
		nr  int
		buf = make([]byte, DP_P2I)
	)

	setRTimeout(hConn)
	nr, err = hConn.Read(buf)

	if nr == len(buf) {

		nr = 0 // reset nr
		ok, stype, len2 := verifyDbcHead(buf, n.sharedKey, tcPool)

		if ok {
			if len2 > 0 {
				setRTimeout(hConn)
				nr, err = io.ReadFull(hConn, buf[:len2])
			}

			if nr == int(len2) && err == nil {
				switch stype {
				case TYPE_NEW:
					return n.handshakeSession(hConn)
				case TYPE_DAT:
					return n.dataSession(hConn)
				}
			}
		}

	} // then may be a prober

	if err == nil {
		err = UNRECOGNIZED_REQ
	}

	// threats OR overlarge time error
	// We could use this log to block threats origin by external tools such as fail2ban.
	log.Warningf("Unrecognized Request from=%s len=%d\n", n.clientAddr, nr)
	return nil, err
}

// new connection
func (n *dbcSerNego) handshakeSession(hConn *hashedConn) (session *Session, err error) {
	defer func() {
		// free ibHash
		n.ibHash = nil
		if e, y := exception.ErrorOf(recover()); y {
			log.Warningln("handshake error", e)
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
func (n *dbcSerNego) dataSession(hConn *hashedConn) (session *Session, err error) {
	token := make([]byte, TKSZ)
	setRTimeout(hConn)
	nr, err := hConn.Read(token)
	// read buf ok
	if nr == len(token) && err == nil {
		// check token ok
		if session := n.sessionMgr.take(token); session != nil {
			// init cipher of new connection
			hConn.cipher = session.cipherFactory.InitCipher(token)
			// check and set identify
			session.identifyConn(hConn.Conn)
			return session, nil
		}
	}
	log.Warningln("Incorrect token from", n.clientAddr, nvl(err, NULL))
	return nil, VALIDATION_FAILED
}

func (n *dbcSerNego) verifyThenDHExchange(conn net.Conn) (key []byte) {
	// client identity segment
	setRTimeout(conn)
	credBuf, err := ReadFullByLen(2, conn)
	ThrowErr(err)

	user, passwd, err := n.idBlockDeserialize(credBuf)
	ThrowErr(err)

	if log.V(1) {
		log.Infoln("Auth client", user)
	}

	allow, err := n.AuthSys.Authenticate(user, passwd)
	if allow {
		n.clientIdentity = user
	} else { // client denied
		log.Warningf("Auth %s:%s failed: %v\n", user, passwd, err)
		// reply failed msg
		conn.Write([]byte{0, 1, AUTH_FAILED})
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

//         |--------- head --------|------- tun params ------|
// | len~2 | version~4 | ibHash~20 | interval~2 | reserved~? | tokens~20N | hash~20
func (n *dbcSerNego) respondTestWithToken(hConn *hashedConn, session *Session) {
	var (
		headLen  = TUN_PARAMS_LEN + 2
		totalLen = TUN_PARAMS_LEN + GENERATE_TOKEN_NUM*TKSZ
		err      error
	)
	// tun params buffer built from rand
	headBuf := make([]byte, headLen)
	// len
	binary.BigEndian.PutUint16(headBuf, uint16(totalLen))
	ofs := 2

	// ver
	ofs += copy(headBuf[ofs:], ito4b(VERSION))

	// ibHash feedback to client for verifying
	ofs += copy(headBuf[ofs:], n.ibHash)

	// params
	n.Server.tunParams.serialize(headBuf[ofs:])

	setWTimeout(hConn)
	_, err = hConn.Write(headBuf) // just header
	ThrowErr(err)

	// send tokens
	tokens := n.sessionMgr.createTokens(session, GENERATE_TOKEN_NUM)
	setWTimeout(hConn)
	_, err = hConn.Write(tokens[1:]) // skip index=0
	ThrowErr(err)

	// validated or throws
	verifyHash(hConn, true)
}

// block: rsa( identity~? | rand )
// hash:  sha1(rand)
func (n *dbcCltNego) idBlockSerialize() (block []byte, e error) {
	identity := n.user + IDENTITY_SEP + n.pass
	idLen, max := len(identity), n.rsaKey.BlockSize()
	if idLen > max-2 {
		e = INVALID_D5PARAMS.Apply("identity too long")
		return
	}
	block = randArray(max)
	block[0] = byte(idLen)
	copy(block[1:], []byte(identity))
	n.ibHash = hash20(block)
	block, e = n.rsaKey.Encrypt(block)
	return
}

func (n *dbcSerNego) idBlockDeserialize(block []byte) (user, pass string, e error) {
	block, e = n.rsaKey.Decrypt(block)
	if e != nil {
		// rsa.ErrDecryption represent cases:
		// 1, C->S is polluted
		// 2, PubKey of client was not paired with PrivKey.
		return
	}
	idOfs := block[0] + 1
	identity := block[1:idOfs]
	fields := strings.Split(string(identity), IDENTITY_SEP)
	if len(fields) != 2 {
		e = INVALID_D5PARAMS.Apply("incorrect identity format")
		return
	}
	user, pass = fields[0], fields[1]
	n.ibHash = hash20(block)
	return
}

func extractKeys(b []byte) (pos, sKey int, hKey uint64) {
	p := len(b) - 10
	sKey = int(binary.BigEndian.Uint16(b[p : p+2]))
	pos = sKey % 0xff
	hKey = binary.BigEndian.Uint64(b[p+2 : p+10])
	return
}

func calculateTimeCounter(withTimeError bool) (tc []uint64) {
	if withTimeError {
		// cur, prev1, next1, prev2, next2...
		tc = make([]uint64, TIME_ERROR<<1+1)
	} else {
		tc = make([]uint64, 1)
	}
	var cur, last uint64 = 0, uint64(time.Now().Unix() / TIME_STEP)
	for i := 0; i < len(tc); i++ {
		cur += last
		if i > 0 {
			if i&1 == 1 {
				cur -= uint64(i)
			} else {
				cur += uint64(i)
			}
		}
		tc[i] = cur
		last, cur = cur, 0
	}
	return tc
}

func makeDbcHead(data byte, secret []byte) []byte {
	randLen := rand.Int() % DP_LEN1 // 8bit
	buf := randArray(randLen + DP_P2I)
	pos, sKey, hKey := extractKeys(secret)

	// actually f is uint16
	f := (randLen << 8) | int(data)
	f = (f + sKey) % DP_MOD
	binary.BigEndian.PutUint16(buf[pos:pos+2], uint16(f))

	sum := siphash.Hash(hKey, calculateTimeCounter(false)[0], buf[:DP_LEN1])
	binary.BigEndian.PutUint64(buf[DP_LEN1:DP_P2I], sum)
	return buf
}

func verifyDbcHead(buf []byte, secret []byte, tc []uint64) (validated bool, data, len2 byte) {
	pos, sKey, hKey := extractKeys(secret)
	p1 := buf[:DP_LEN1]

	var sum, cltSum uint64
	cltSum = binary.BigEndian.Uint64(buf[DP_LEN1:DP_P2I])

	for i := 0; !validated && i < len(tc); i++ {
		sum = siphash.Hash(hKey, tc[i], p1)
		validated = cltSum == sum
	}

	if !validated {
		return
	}

	z := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
	z = (z - sKey + DP_MOD) % DP_MOD
	len2, data = byte(z>>8), byte(z&0xff)
	return
}
