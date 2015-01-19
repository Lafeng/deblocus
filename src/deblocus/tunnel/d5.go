package tunnel

import (
	"bytes"
	"crypto/sha1"
	"deblocus/auth"
	"deblocus/exception"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	log "golang/glog"
	"io"
	mrand "math/rand"
	"net"
	"strconv"
	"time"
)

const (
	D5              = 0xd5
	IPV4            = byte(1)
	DOMAIN          = byte(3)
	IPV6            = byte(4)
	SOCKS5_VER      = byte(5)
	NULL            = ""
	DMLEN           = 384
	TT_TOKEN_OFFSET = SzTk + 2
)

var (
	// socks5 exceptions
	INVALID_SOCKS5_HEADER  = exception.New(0xff, "Invalid socks5 header")
	INVALID_SOCKS5_REQUEST = exception.New(0x07, "Invalid socks5 request")
	GENERAL_FAILURE        = exception.New(0x01, "General failure")
	HOST_UNREACHABLE       = exception.New(0x04, "Host is unreachable")
	// D5 exceptions
	INVALID_D5PARAMS   = exception.NewW("Invalid D5Params")
	D5SER_UNREACHABLE  = exception.NewW("D5Server is unreachable")
	VALIDATE_FAILURE   = exception.NewW("Validate failure")
	TRANS_SESSION      = exception.NewW("TT")
	HASH_INCONSISTENCE = exception.NewW("Hash inconsistence")
)

func ThrowErr(e interface{}) {
	if e != nil {
		panic(e)
	}
}

func ThrowIf(condition bool, e interface{}) {
	if condition {
		panic(e)
	}
}

func SafeClose(conn net.Conn) {
	defer func() {
		_ = recover()
	}()
	if conn != nil {
		conn.Close()
	}
}

// make lenght=alen array, and header 16byte padding with rand
func byteArrayWithRand16B(alen int) []byte {
	array := make([]byte, alen)
	mrand.Seed(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(array, uint64(mrand.Int63()))
	binary.LittleEndian.PutUint64(array[8:], uint64(mrand.Int63()))
	return array
}

// read by the first segment indicated the following segment length
// len_inByte: first segment length in byte
func ReadFullByLen(len_inByte int, reader io.Reader) (buf []byte, err error) {
	lb := make([]byte, len_inByte)
	_, err = reader.Read(lb)
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
		s.err = INVALID_SOCKS5_HEADER
		return
	}
	ver, nmethods := buf[0], int(buf[1])
	if ver != SOCKS5_VER || nmethods < 1 {
		s.err = INVALID_SOCKS5_HEADER
		return
	}
	buf = make([]byte, nmethods+1) // consider method non-00
	n, err := io.ReadAtLeast(s.conn, buf, nmethods)
	if err != nil || n != nmethods {
		s.err = INVALID_SOCKS5_HEADER
		log.Warningln("invalid header: " + hex.EncodeToString(buf))
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
	var skip int
	switch atyp {
	case IPV4:
		host = net.IP(buf[:net.IPv4len]).String()
		skip = net.IPv4len
	case IPV6:
		host = net.IP(buf[:net.IPv6len]).String()
		skip = net.IPv6len
	case DOMAIN:
		dlen := int(buf[0])
		host = string(buf[1 : dlen+1])
		skip = dlen + 1
	default:
		s.err = INVALID_SOCKS5_REQUEST
		return NULL
	}
	var dst_port = binary.BigEndian.Uint16(buf[skip : skip+2])
	return host + ":" + strconv.FormatInt(int64(dst_port), 10)
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

type S5Target struct {
	dst  *net.TCPAddr
	host string
}

func (s *S5Target) parseSocks5Target(buf []byte) (net.Conn, error) {
	var domain string
	atyp := buf[0]
	buf = buf[1:]
	s.dst = new(net.TCPAddr)
	switch atyp {
	case IPV4:
		s.dst.IP = net.IP(buf[:net.IPv4len])
		buf = buf[net.IPv4len:]
	case IPV6:
		s.dst.IP = net.IP(buf[:net.IPv6len])
		buf = buf[net.IPv6len:]
	case DOMAIN:
		dlen := int(buf[0])
		domain = string(buf[1 : dlen+1])
		buf = buf[dlen+1:]
	default:
		return nil, INVALID_SOCKS5_REQUEST
	}
	var dst_port = binary.BigEndian.Uint16(buf[:2])
	if domain == "" {
		s.dst.Port = int(dst_port)
		return net.DialTCP("tcp", nil, s.dst)
	} else {
		s.host = domain + ":" + strconv.FormatInt(int64(dst_port), 10)
		return net.Dial("tcp", s.host)
	}
}

func hash20(byteArray []byte) []byte {
	sha := sha1.New()
	sha.Write(byteArray)
	return sha.Sum(nil)
}

type d5CNegotiation struct {
	*D5Params
	dhKeys        *DHKeyPair
	identity      string
	cipherFactory *CipherFactory
	token         []byte
}

func (nego *d5CNegotiation) negotiate() (sconn *Conn) {
	conn, err := net.Dial("tcp", nego.d5sAddrStr)
	ThrowIf(err != nil, D5SER_UNREACHABLE)
	sconn = NewConnWithHash(conn.(*net.TCPConn))
	err = nego.requestAuthAndDHExchange(sconn)
	ThrowErr(err)
	err = nego.finishDHExThenSetupCipher(sconn)
	ThrowErr(err)
	sconn.cipher = nego.cipherFactory.NewCipher()
	err = nego.validateAndGetTokens(sconn)
	ThrowErr(err)
	return
}

// send
// obf~256 | idBlock(enc)~128 | dhPubLen~2 | dhPub~?
func (nego *d5CNegotiation) requestAuthAndDHExchange(conn *Conn) (err error) {
	t := 16
	// obfuscated header 256
	obf := byteArrayWithRand16B(256)
	_s, _d := obf[:16], obf[16:]
	for ; t > 1; t-- {
		copy(_d, _s)
		_d = _d[16:]
	}
	obf[0xd5] = D5
	obf[0xff] = 0
	// send identity using rsa
	// identity must be less than 117byte for once encrypting
	idBlock := make([]byte, 128)
	identity := fmt.Sprintf("%s\x00%s", nego.user, nego.pass)
	nego.identity = identity
	idBlock, err = RSAEncrypt([]byte(identity), nego.sPub)

	buf := new(bytes.Buffer)
	buf.Write(obf)
	buf.Write(idBlock)
	buf.Write(nego.dhKeys.pubLen)
	buf.Write(nego.dhKeys.pub)
	if log.V(3) {
		log.Infof("CNegotiation send: \n%s", hex.Dump(buf.Bytes()))
	}
	_, err = conn.Write(buf.Bytes())
	return
}

// recv: rhPub~2+256
func (nego *d5CNegotiation) finishDHExThenSetupCipher(conn *Conn) (err error) {
	buf, err := ReadFullByLen(2, conn)
	ThrowErr(err)
	if len(buf) == 1 {
		switch buf[0] {
		case 0xff:
			err = auth.AUTH_FAILED
		default:
			err = VALIDATE_FAILURE.Apply("indentity")
		}
		return
	}
	secret := takeSharedKey(nego.dhKeys, buf)
	nego.cipherFactory = NewCipherFactory(nego.algoId, secret)
	if log.V(3) {
		log.Infof("secretKey: \n%s", hex.Dump(secret))
	}
	return
}

func (nego *d5CNegotiation) validateAndGetTokens(sconn *Conn) (err error) {
	rHash := sconn.RHashSum() // 2+256
	wHash := sconn.WHashSum() // 642
	_, err = sconn.Write(rHash)
	ThrowErr(err)
	oHash := make([]byte, SzTk)
	_, err = sconn.Read(oHash)
	if !bytes.Equal(wHash, oHash) {
		log.Errorln("Server hash/r is inconsistence with the client/w")
		log.Errorf("rHash: [% x] wHash: [% x]\n", rHash, wHash)
		log.Errorf("oHash: [% x]\n", oHash)
		return HASH_INCONSISTENCE
	}
	tokenBuf := make([]byte, GENERATE_TOKEN_NUM*SzTk)
	n, err := io.ReadFull(sconn, tokenBuf)
	if log.V(2) {
		log.Errorln("Got token Len=", n/SzTk)
	}
	ThrowErr(err)
	nego.token = tokenBuf
	return
}

//
// d5Server negotiation
//
type d5SNegotiation struct {
	*Server
	clientAddr     string
	clientIdentity string
	remnant        []byte
}

func (nego *d5SNegotiation) negotiate(conn *Conn) (session *Session, err error) {
	buf := make([]byte, DMLEN)
	n, err := conn.Read(buf)
	nego.clientAddr = conn.RemoteAddr().String()
	if n == DMLEN {
		if buf[19] == buf[20] && buf[21] == D5 {
			conn.FreeHash()
			return nego.transSession(conn, buf)
		}
		if buf[0xd5] == D5 && buf[0xff] == 0 {
			skey, err := nego.verifyThenDHExchange(conn, buf[256:])
			ThrowErr(err)
			cf := NewCipherFactory(nego.AlgoId, skey)
			conn.cipher = cf.NewCipher()
			session = NewSession(conn, cf, nego.clientIdentity)
			err = nego.respondTestWithToken(conn, session)
			ThrowErr(err)
			return session, err
		}
	}
	log.Warningf("Unrecognized Request from=%s len=%d\n", conn.RemoteAddr(), n)
	return nil, errors.New("")
}

func (nego *d5SNegotiation) transSession(conn *Conn, buf []byte) (session *Session, err error) {
	token := buf[:SzTk]
	if ss := nego.sessionMgr.take(token); ss != nil {
		nego.remnant = buf[SzTk+2:]
		return ss, TRANS_SESSION
	}
	log.Warningln("Client used incorrect token")
	return nil, VALIDATE_FAILURE
}

func (nego *d5SNegotiation) verifyThenDHExchange(conn net.Conn, credBuf []byte) (key []byte, err error) {
	userIdentity, err := RSADecrypt(credBuf, nego.RSAKeys.priv)
	ThrowErr(err)
	clientIdentity := string(userIdentity)
	log.Infof("Auth clientIdentity: %s\n", clientIdentity)
	allow, ex := nego.AuthSys.Authenticate(userIdentity)
	cDHPub, err := ReadFullByLen(2, conn)
	if !allow {
		log.Infof("Auth %s failed: %v\n", clientIdentity, ex)
		conn.Write([]byte{0, 1, 0xff})
		return nil, ex
	}
	nego.clientIdentity = clientIdentity
	key = takeSharedKey(nego.dhKeys, cDHPub)
	if log.V(3) {
		log.Infof("sharedkey: \n%s", hex.Dump(key))
	}
	buf := new(bytes.Buffer)
	buf.Write(nego.dhKeys.pubLen)
	buf.Write(nego.dhKeys.pub)
	_, err = buf.WriteTo(conn)
	return
}

// hash~20 | tokens~20N
func (nego *d5SNegotiation) respondTestWithToken(sconn *Conn, session *Session) (err error) {
	rHash := sconn.RHashSum()
	wHash := sconn.WHashSum()
	oHash := make([]byte, SzTk)
	_, err = sconn.Read(oHash)
	ThrowErr(err)
	if !bytes.Equal(wHash, oHash) {
		log.Errorln("Remote hash/r not equals self/w")
		log.Errorf("rHash: [% x] wHash: [% x]\n", rHash, wHash)
		log.Errorf("oHash: [% x]\n", oHash)
		return HASH_INCONSISTENCE
	}
	_, err = sconn.Write(rHash)
	ThrowErr(err)
	tokens := nego.sessionMgr.createTokens(session, GENERATE_TOKEN_NUM)
	_, err = sconn.Write(tokens)
	return
}
