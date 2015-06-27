package tunnel

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/spance/deblocus/auth"
	"github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	D5                 = 0xd5
	IPV4               = byte(1)
	DOMAIN             = byte(3)
	IPV6               = byte(4)
	SOCKS5_VER         = byte(5)
	NULL               = ""
	DMLEN              = 384
	TT_TOKEN_OFFSET    = TKSZ + 2
	GENERAL_SO_TIMEOUT = 10 * time.Second
	TUN_PARAMS_LEN     = 32
	TP_INTERVAL_OFS    = 4
)

var (
	VERSION uint32
	// socks5 exceptions
	INVALID_SOCKS5_HEADER  = exception.New(0xff, "Invalid socks5 header")
	INVALID_SOCKS5_REQUEST = exception.New(0x07, "Invalid socks5 request")
	GENERAL_FAILURE        = exception.New(0x01, "General failure")
	HOST_UNREACHABLE       = exception.New(0x04, "Host is unreachable")
	// D5 exceptions
	INVALID_D5PARAMS     = exception.NewW("Invalid D5Params")
	D5SER_UNREACHABLE    = exception.NewW("D5Server is unreachable")
	VALIDATION_FAILED    = exception.NewW("Validation failed")
	NEGOTIATION_FAILED   = exception.NewW("Negotiation failed")
	DATATUN_SESSION      = exception.NewW("DT")
	HASH_INCONSISTENCE   = exception.NewW("Hash inconsistence")
	INCOMPATIBLE_VERSION = exception.NewW("Incompatible version")
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

// make lenght=alen array, and header padding with randLen random
func randArray(aLen int, randLen int) []byte {
	array := make([]byte, aLen)
	//rand.Seed(time.Now().UnixNano())
	io.ReadAtLeast(rand.Reader, array, randLen)
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
		log.Warningln("invalid socks5 header: " + hex.EncodeToString(buf))
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

func hash20(byteArray []byte) []byte {
	sha := sha1.New()
	sha.Write(byteArray)
	return sha.Sum(nil)
}

func setSoTimeout(conn net.Conn) {
	e := conn.SetDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
	ThrowErr(e)
}

func ito4b(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	return buf
}

type tunParams struct {
	cipherFactory *CipherFactory
	token         []byte
	interval      int
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

func (nego *d5CNegotiation) negotiate() (*Conn, *tunParams) {
	conn, err := net.DialTCP("tcp", nil, nego.d5sAddr)
	ThrowIf(err != nil, D5SER_UNREACHABLE)
	setSoTimeout(conn)
	var sconn = NewConnWithHash(conn)
	err = nego.requestAuthAndDHExchange(sconn)
	ThrowErr(err)
	var t = new(tunParams)
	err = nego.finishDHExThenSetupCipher(sconn, t)
	ThrowErr(err)
	sconn.cipher = t.cipherFactory.NewCipher(nil)
	sconn.identifier = nego.RemoteId()
	err = nego.validateAndGetTokens(sconn, t)
	ThrowErr(err)
	return sconn.Conn, t
}

// send
// obf~256 | idBlock(enc)~128 | dhPubLen~2 | dhPub~?
func (nego *d5CNegotiation) requestAuthAndDHExchange(conn *hashedConn) (err error) {
	// obfuscated header 256
	obf := randArray(256, 256)
	obf[0xd5] = D5
	obf[0xff] = 0
	// send identity using rsa
	// identity must be less than 117byte for once encrypting
	idBlock := make([]byte, 128)
	identity := fmt.Sprintf("%s\x00%s", nego.user, nego.pass)
	idBlock, err = RSAEncrypt([]byte(identity), nego.sPub)

	buf := new(bytes.Buffer)
	buf.Write(obf)
	buf.Write(idBlock)
	buf.Write(nego.dhKeys.pubLen)
	buf.Write(nego.dhKeys.pub)
	if log.V(5) {
		dumpHex("d5CNegotiation send", buf.Bytes())
	}
	_, err = conn.Write(buf.Bytes())
	return
}

// recv: rhPub~2+256
func (nego *d5CNegotiation) finishDHExThenSetupCipher(conn *hashedConn, t *tunParams) (err error) {
	buf, err := ReadFullByLen(2, conn)
	ThrowErr(err)
	if len(buf) == 1 {
		switch buf[0] {
		case 0xff:
			err = auth.AUTH_FAILED
		default:
			err = VALIDATION_FAILED.Apply("indentity")
		}
		return
	}
	secret := takeSharedKey(nego.dhKeys, buf)
	t.cipherFactory = NewCipherFactory(nego.algo, secret)
	if log.V(5) {
		dumpHex("Sharedkey", secret)
	}
	return
}

func (nego *d5CNegotiation) validateAndGetTokens(sconn *hashedConn, t *tunParams) (err error) {
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
			return INCOMPATIBLE_VERSION.Apply(oVerStr)
		}
	}
	t.interval = int(binary.BigEndian.Uint16(buf[TP_INTERVAL_OFS:]))
	t.tunQty = int(buf[TP_INTERVAL_OFS+2])
	t.token = buf[TUN_PARAMS_LEN:]
	if log.V(2) {
		n := len(buf) - TUN_PARAMS_LEN
		log.Infof("Got tokens length=%d\n", n/TKSZ)
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
		return HASH_INCONSISTENCE
	}
	return
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

func (nego *d5SNegotiation) negotiate(hconn *hashedConn) (session *Session, err error) {
	setSoTimeout(hconn)
	nego.clientAddr = hconn.RemoteAddr().String()
	var (
		nr  int
		buf = make([]byte, DMLEN)
	)
	nr, err = hconn.Read(buf)
	ThrowErr(err)

	if nr == TKSZ+1 && uint(int8(buf[TKSZ-1])+int8(buf[TKSZ]))&0xff == D5 {
		return nego.transSession(hconn, buf)
	}
	if nr == DMLEN && buf[0xd5] == D5 && buf[0xff] == 0 {
		var (
			skey []byte
			cf   *CipherFactory
		)
		skey, err = nego.verifyThenDHExchange(hconn, buf[256:])
		ThrowErr(err)
		cf = NewCipherFactory(nego.Algo, skey)
		hconn.cipher = cf.NewCipher(nil)
		session = NewSession(hconn.Conn, cf, nego.clientIdentity)
		err = nego.respondTestWithToken(hconn, session)
		return
	}
	log.Warningf("Unrecognized Request from=%s len=%d\n", hconn.RemoteAddr(), nr)
	return nil, NEGOTIATION_FAILED
}

func (nego *d5SNegotiation) transSession(conn *hashedConn, buf []byte) (session *Session, err error) {
	token := buf[:TKSZ]
	if ss := nego.sessionMgr.take(token); ss != nil {
		nego.tokenBuf = buf
		return ss, DATATUN_SESSION
	}
	log.Warningln("Incorrect token from", conn.RemoteAddr())
	return nil, VALIDATION_FAILED
}

func (nego *d5SNegotiation) verifyThenDHExchange(conn net.Conn, credBuf []byte) (key []byte, err error) {
	userIdentity, err := RSADecrypt(credBuf, nego.RSAKeys.priv)
	ThrowErr(err)
	clientIdentity := string(userIdentity)
	if log.V(1) {
		log.Infoln("Auth clientIdentity:", clientIdentity)
	}
	allow, ex := nego.AuthSys.Authenticate(userIdentity)
	cDHPub, err := ReadFullByLen(2, conn)
	if !allow {
		log.Warningf("Auth %s failed: %v\n", clientIdentity, ex)
		conn.Write([]byte{0, 1, 0xff})
		return nil, ex
	}
	nego.clientIdentity = clientIdentity
	key = takeSharedKey(nego.dhKeys, cDHPub)
	if log.V(5) {
		dumpHex("Sharedkey", key)
	}
	buf := new(bytes.Buffer)
	buf.Write(nego.dhKeys.pubLen)
	buf.Write(nego.dhKeys.pub)
	_, err = buf.WriteTo(conn)
	return
}

//         |------------- tun params ------------|
// | len~2 | version~4 | interval~2 | reserved~? | tokens~20N ; hash~20
func (nego *d5SNegotiation) respondTestWithToken(sconn *hashedConn, session *Session) (err error) {
	var headLen = TUN_PARAMS_LEN + 2
	// tun params
	tpBuf := randArray(headLen, headLen)
	binary.BigEndian.PutUint16(tpBuf, uint16(TUN_PARAMS_LEN+GENERATE_TOKEN_NUM*TKSZ))
	copy(tpBuf[2:], ito4b(VERSION))
	binary.BigEndian.PutUint16(tpBuf[2+4:], CTL_PING_INTERVAL)
	tpBuf[8] = PARALLEL_TUN_QTY

	_, err = sconn.Write(tpBuf)
	ThrowErr(err)
	tokens := nego.sessionMgr.createTokens(session, GENERATE_TOKEN_NUM)
	_, err = sconn.Write(tokens)
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
		return HASH_INCONSISTENCE
	}
	_, err = sconn.Write(rHash)
	ThrowErr(err)
	return
}
