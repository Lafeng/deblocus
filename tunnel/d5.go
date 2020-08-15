package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Lafeng/deblocus/auth"
	"github.com/Lafeng/deblocus/crypto"
	"github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/glog"
	"github.com/dchest/siphash"
)

const (
	AUTH_PASS byte = 0xff
	TYPE_NEW  byte = 0xfb
	TYPE_RES  byte = 0xf1
)

const (
	GENERAL_SO_TIMEOUT = 10 * time.Second

	DPH_LEN1   = 256
	DPH_P2     = 256 + 8 // part-2 offset
	DPH_MOD    = 65536
	TIME_STEP  = 60 // seconds
	TIME_ERROR = 1  // minutes

	NULL         = ""
	IDENTITY_SEP = "\x00"
)

const (
	EFB_CODE_PRE_AUTH byte = 1
)

const (
	KCP_FEC_DATASHARD   = 10
	KCP_FEC_PARITYSHARD = 3
)

const (
	EMSG_PRE_AUTH   = "Your clock is not in sync with the server, or your client credential is invalid."
	EMSG_HIDDEN_EFB = "Maybe the connection was reset, " + EMSG_PRE_AUTH
)

var (
	// for main package injection
	VERSION    uint32
	VER_STRING string
	DEBUG      bool
)

var (
	// D5 exceptions
	ILLEGAL_STATE        = exception.New("Invalid State")
	VALIDATION_FAILED    = exception.New("Validation Failed")
	INCONSISTENT_HASH    = exception.New("Inconsistent Hashsum")
	INCOMPATIBLE_VERSION = exception.New("Incompatible Version")
	UNRECOGNIZED_REQ     = exception.New("Unrecognized Request")
	ERR_PRE_AUTH_UNKNOWN = exception.New("Pre-auth failed")
	ERR_PRE_AUTH         = exception.New(EMSG_PRE_AUTH)
	ERR_HIDDEN_EFB       = exception.New(EMSG_HIDDEN_EFB)
	ABORTED_ERROR        = exception.New("")
)

// len_inByte enum: 1,2,4
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
	if len(buf) > 0 {
		_, err = io.ReadFull(reader, buf)
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
func (p *tunParams) serialize() []byte {
	var buf = make([]byte, 4)
	binary.BigEndian.PutUint16(buf, uint16(p.pingInterval))
	binary.BigEndian.PutUint16(buf[2:], uint16(p.parallels))
	return buf
}

// read from raw buf
// for client
func (p *tunParams) deserialize(buf []byte) {
	p.pingInterval = int(binary.BigEndian.Uint16(buf))
	p.parallels = int(binary.BigEndian.Uint16(buf[2:]))
}

func compareVersion(buf []byte) error {
	// compare version with remote
	myVer := VERSION
	rVer := binary.BigEndian.Uint32(buf)
	if rVer > myVer {
		rVerStr := fmt.Sprintf("%d.%d.%04d", rVer>>24, (rVer>>16)&0xFF, rVer&0xFFFF)
		myVer >>= 16
		rVer >>= 16
		if myVer == rVer {
			log.Warningf("Caution !!! Please upgrade to new version, remote is v%s\n", rVerStr)
		} else {
			return INCOMPATIBLE_VERSION.Apply(rVerStr)
		}
	}
	return nil
}

const (
	DH_METHOD = "ECC-P256"
)

//
// d5 client handshake protocol
//
type d5ClientProtocol struct {
	transport *Transport
	dhKey     crypto.DHKE
	dbcHello  []byte
	sRand     []byte
}

func newD5ClientProtocol(c *Client) *d5ClientProtocol {
	return &d5ClientProtocol{
		transport: c.transport,
	}
}

func (n *d5ClientProtocol) Connect(p *tunParams) (conn *Conn, err error) {
	var rawConn net.Conn
	defer func() {
		n.dbcHello, n.sRand = nil, nil
		if exception.Catch(recover(), &err) {
			SafeClose(rawConn)
			if t, y := err.(*exception.Exception); y {
				if t.Origin != nil {
					t = t.Origin
				}
				var exitCode int
				// must terminate
				switch t {
				case ERR_PRE_AUTH, ERR_PRE_AUTH_UNKNOWN, ERR_HIDDEN_EFB:
					exitCode = 2
				case INCOMPATIBLE_VERSION:
					exitCode = 3
				}
				if exitCode > 0 {
					line := string(bytes.Repeat([]byte{'+'}, 30))
					log.Warningln(line)
					log.Warningln(err)
					log.Warningln(line)
					os.Exit(exitCode)
				}
			}
		}
	}()
	rawConn, err = n.transport.Dail()
	n.dhKey, _ = crypto.NewDHKey(DH_METHOD)
	if err != nil {
		return
	}

	conn = NewConn(rawConn, nullCipherKit)
	if err = n.requestDHExchange(conn); err != nil {
		return
	}
	var cf *CipherFactory
	cf, err = n.finishDHExchange(conn)
	if err != nil {
		return
	}
	if err = n.validate(conn); err != nil {
		return
	}
	if err = n.authThenFinishSetting(conn, p); err != nil {
		return
	}
	p.cipherFactory = cf
	conn.SetId(n.transport.provider, false)
	return
}

func (n *d5ClientProtocol) ResumeSession(p *tunParams, token []byte) (conn *Conn, err error) {
	var rawConn net.Conn
	rawConn, err = n.transport.Dail()
	if err != nil {
		exception.Spawn(&err, "resume: connnecting")
		return
	}
	conn = NewConn(rawConn, nullCipherKit)
	obf := makeDbcHello(TYPE_RES, preSharedKey(n.transport.pubKey))
	w := newMsgWriter()
	w.WriteMsg(obf)
	w.WriteMsg(token)

	err = w.WriteTo(conn)
	if err != nil {
		exception.Spawn(&err, "resume: write")
		return
	}

	conn.SetupCipher(p.cipherFactory, token)
	conn.SetId(n.transport.provider, false)
	return conn, nil
}

// 1-send dbcHello,dhPub
// dbcHello~256 | dhPubLen~2 | dhPub~?
func (n *d5ClientProtocol) requestDHExchange(conn *Conn) (err error) {
	// obfuscated header
	obf := makeDbcHello(TYPE_NEW, preSharedKey(n.transport.pubKey))
	w := newMsgWriter().WriteMsg(obf)
	if len(obf) > DPH_P2 {
		n.dbcHello = obf[DPH_P2:]
	} else {
		n.dbcHello = obf
	}

	// dhke
	pub := n.dhKey.ExportPubKey()
	w.WriteL2Msg(pub)

	setWTimeout(conn)
	err = w.WriteTo(conn)
	exception.Spawn(&err, "dh: write connection")
	return
}

// read dhPub from server and verify sign
// dhPubLen~1 | dhPub~? | signLen~1 | sign~? | rand
func (n *d5ClientProtocol) finishDHExchange(conn *Conn) (cf *CipherFactory, err error) {
	var dhk, dhkSign []byte
	// recv: rhPub~2+256 or ecdhPub~2+32
	setRTimeout(conn)
	dhk, err = ReadFullByLen(1, conn)
	if err != nil {
		if len(dhk) > 0 { // can recv error feedback
			code, rt := parseErrorFeedback(dhk)
			rTime := rt.Format(time.StampMilli)
			switch code {
			case EFB_CODE_PRE_AUTH:
				err = ERR_PRE_AUTH.Apply("Remote Time " + rTime)
			default:
				err = ERR_PRE_AUTH_UNKNOWN.Apply("Remote Time " + rTime)
			}

		} else { // no error feedback OR network error occurred actually
			if IsClosedError(err) {
				err = ERR_HIDDEN_EFB
			} else { // other unknown error
				exception.Spawn(&err, "dh: read response")
			}
		}
		return
	}

	setRTimeout(conn)
	dhkSign, err = ReadFullByLen(1, conn)
	if err != nil {
		exception.Spawn(&err, "dh: read sign")
		return
	}

	if !DSAVerify(n.transport.pubKey, dhkSign, dhk) {
		// MITM ?
		return nil, VALIDATION_FAILED
	}

	key, err := n.dhKey.ComputeKey(dhk)
	if err != nil {
		exception.Spawn(&err, "dh: compute")
		return
	}

	n.sRand, err = ReadFullByLen(1, conn)
	if err != nil {
		exception.Spawn(&err, "srand: read connection")
		return
	}

	// setup cipher
	cf = NewCipherFactory(n.transport.cipher, key, n.dbcHello)
	conn.SetupCipher(cf, n.sRand)
	return
}

// verify encrypted message
// hashHello, version
func (n *d5ClientProtocol) validate(conn *Conn) error {
	setRTimeout(conn)
	hashHello, err := ReadFullByLen(1, conn)
	if err != nil {
		return exception.Spawn(&err, "validate: read connection")
	}

	myHashHello := hash256(n.dbcHello)
	if !bytes.Equal(hashHello, myHashHello) {
		// MITM ?
		return INCONSISTENT_HASH
	}

	ver, err := ReadFullByLen(1, conn)
	if err != nil {
		return exception.Spawn(&err, "ver: read connection")
	}
	if err = compareVersion(ver); err != nil {
		return err
	}
	return nil
}

// report hashRand0 then request authentication
// get tun params and tokens
func (n *d5ClientProtocol) authThenFinishSetting(conn *Conn, t *tunParams) error {
	var err error
	w := newMsgWriter()
	// hash sRand
	w.WriteL1Msg(hash256(n.sRand))
	// identity
	w.WriteL1Msg(n.serializeIdentity())

	setWTimeout(conn)
	err = w.WriteTo(conn)
	if err != nil {
		return exception.Spawn(&err, "auth: write connection")
	}

	setRTimeout(conn)
	var buf, params []byte
	buf, err = ReadFullByLen(1, conn)
	if err != nil {
		return exception.Spawn(&err, "auth: read connection")
	}
	// auth_result
	switch buf[0] {
	case AUTH_PASS:
	default:
		return auth.AUTH_FAILED
	}

	// parse params
	params, err = ReadFullByLen(2, conn)
	if err != nil {
		return exception.Spawn(&err, "param: read connection")
	}
	t.deserialize(params)

	t.token, err = ReadFullByLen(2, conn)
	if err != nil {
		return exception.Spawn(&err, "token: read connection")
	}
	if len(t.token) < TKSZ || len(t.token)%TKSZ != 0 {
		return ILLEGAL_STATE.Apply("incorrect token")
	}
	if log.V(log.LV_TOKEN) {
		log.Infof("Received tokens size=%d\n", len(t.token)/TKSZ)
	}

	return nil
}

//
// Server handshake protocol
//
type d5ServerProtocol struct {
	*Server
	dbcHello     []byte
	sRand        []byte
	clientAddr   net.Addr
	isNewSession bool
}

func newD5ServerProtocol(s *Server, peer net.Addr) *d5ServerProtocol {
	return &d5ServerProtocol{
		Server:     s,
		clientAddr: peer,
	}
}

// external conn lifecycle
func (n *d5ServerProtocol) Connect(conn *Conn, tcPool []uint64) (session *Session, err error) {
	var (
		nr  int
		buf = make([]byte, DPH_P2)
	)

	setRTimeout(conn)
	nr, err = conn.Read(buf)

	if nr == len(buf) {

		nr = 0 // reset nr
		ok, stype, len2 := verifyDbcHello(buf, n.sharedKey, tcPool)

		if ok {
			if len2 > 0 {
				setRTimeout(conn)
				nr, err = io.ReadFull(conn, buf[:len2])
				n.dbcHello = buf[:len2]
			} else {
				n.dbcHello = buf
			}

			if nr == int(len2) && err == nil {
				switch stype {
				case TYPE_NEW:
					return n.fullHandshake(conn)
				case TYPE_RES:
					return n.resumeSession(conn)
				}
			}

		} else if n.errFeedback { // can give error feedback
			sendErrorFeedback(conn, EFB_CODE_PRE_AUTH)
			log.Warningf("Failed to pre-auth client from=%s", n.clientAddr)
			return nil, UNRECOGNIZED_REQ
		}

	} // then may be a prober

	// threats OR overlarge time error
	// We could use this log to block threats origin by external tools such as fail2ban.
	log.Warningf("Unrecognized Request from=%s len=%d\n", n.clientAddr, nr)
	return nil, nvl(err, UNRECOGNIZED_REQ).(error)
}

// new connection
func (n *d5ServerProtocol) fullHandshake(conn *Conn) (session *Session, err error) {
	defer func() {
		if exception.Catch(recover(), &err) {
			if t, y := err.(*exception.Exception); y && t.Origin == ABORTED_ERROR {
				log.Warningf("Handshake aborted by client from=%s", n.clientAddr)
			} else {
				log.Warningf("Handshake error=%v from=%s", err, n.clientAddr)
			}
		}
	}()
	var cf *CipherFactory
	n.isNewSession = true
	cf, err = n.finishDHExchange(conn)
	if err != nil {
		return
	}
	session = n.NewSession(cf)
	err = n.authenticate(conn, session)
	return
}

// quick resume session
func (n *d5ServerProtocol) resumeSession(conn *Conn) (session *Session, err error) {
	token := make([]byte, TKSZ)
	setRTimeout(conn)
	// just read once
	nr, err := conn.Read(token)
	if nr == len(token) && err == nil {
		// check token ok
		if session := n.sessionMgr.take(token); session != nil {
			// reuse cipherFactory to init cipher
			conn.SetupCipher(session.cipherFactory, token)
			// identify connection
			conn.SetId(session.uid, true)
			return session, nil
		}
	}
	log.Warningln("Incorrect token from", n.clientAddr, nvl(err, NULL))
	return nil, VALIDATION_FAILED
}

// finish DHE
// 1, dhPub, dhSign, rand
// 2, hashHello, version
func (n *d5ServerProtocol) finishDHExchange(conn *Conn) (cf *CipherFactory, err error) {
	var dhPub, key []byte
	dhKey, _ := crypto.NewDHKey(DH_METHOD)

	setRTimeout(conn)
	dhPub, err = ReadFullByLen(2, conn)
	if err != nil {
		exception.Spawn(&err, "dh: read connection")
		return
	}

	w := newMsgWriter()
	myDhPub := dhKey.ExportPubKey()
	w.WriteL1Msg(myDhPub)

	myDhSign := DSASign(n.privateKey, myDhPub)
	w.WriteL1Msg(myDhSign)

	n.sRand = randMinArray()
	w.WriteL1Msg(n.sRand)

	setWTimeout(conn)
	err = w.WriteTo(conn)
	if err != nil {
		exception.Spawn(&err, "dh: write connection")
		return
	}

	key, err = dhKey.ComputeKey(dhPub)
	if err != nil {
		exception.Spawn(&err, "dh: compute")
		return
	}

	// setup cipher
	cf = NewCipherFactory(n.Cipher, key, n.dbcHello)
	conn.SetupCipher(cf, n.sRand)

	// encrypted
	w.WriteL1Msg(hash256(n.dbcHello))
	w.WriteL1Msg(ito4b(VERSION))

	setWTimeout(conn)
	err = w.WriteTo(conn)
	if err != nil {
		exception.Spawn(&err, "em: write connection")
		return
	}
	return
}

func (n *d5ServerProtocol) authenticate(conn *Conn, session *Session) error {
	var err error
	setRTimeout(conn)
	hashSRand, err := ReadFullByLen(1, conn)
	if err != nil {
		// client aborted
		if IsClosedError(err) {
			return ABORTED_ERROR.Apply(err)
		} else {
			return exception.Spawn(&err, "srand: read connection")
		}
	}

	myHashSRand := hash256(n.sRand)
	if !bytes.Equal(hashSRand, myHashSRand) {
		// MITM ?
		return INCONSISTENT_HASH
	}

	// client identity
	setRTimeout(conn)
	idBuf, err := ReadFullByLen(1, conn)
	if err != nil {
		return exception.Spawn(&err, "auth: read connection")
	}

	user, passwd, err := n.deserializeIdentity(idBuf)
	if err != nil {
		return err
	}

	if log.V(log.LV_LOGIN) {
		log.Infoln("Login request:", user)
	}

	pass, err := n.AuthSys.Authenticate(user, passwd)
	if !pass {
		// authSys denied
		log.Warningf("Auth %s:%s failed: %v\n", user, passwd, err)
		// reply failed msg
		conn.Write([]byte{1, 0})
		return VALIDATION_FAILED
	}

	session.indentifySession(user, conn)
	w := newMsgWriter()
	w.WriteL1Msg([]byte{AUTH_PASS})
	w.WriteL2Msg(n.tunParams.serialize())
	// send tokens
	num := maxInt(GENERATE_TOKEN_NUM, n.Parallels+2)
	tokens := n.sessionMgr.createTokens(session, num)
	w.WriteL2Msg(tokens[1:]) // skip index=0

	setWTimeout(conn)
	err = w.WriteTo(conn)
	return exception.Spawn(&err, "setting: write connection")
}

func (n *d5ClientProtocol) serializeIdentity() []byte {
	identity := n.transport.user + IDENTITY_SEP + n.transport.pass
	if len(identity) > 255 {
		panic("identity too long")
	}
	return []byte(identity)
}

func (n *d5ServerProtocol) deserializeIdentity(block []byte) (user, pass string, e error) {
	fields := strings.Split(string(block), IDENTITY_SEP)
	if len(fields) != 2 {
		e = ILLEGAL_STATE.Apply("incorrect identity format")
		return
	}
	user, pass = fields[0], fields[1]
	return
}

func parseErrorFeedback(buf []byte) (code byte, rt time.Time) {
	if len(buf) == 0xff && buf[0] == 0xee {
		code = buf[1]
		if rt.UnmarshalBinary(buf[3:18]) == nil {
			return
		}
	}
	panic(ERR_PRE_AUTH_UNKNOWN)
}

func sendErrorFeedback(conn net.Conn, code byte) {
	var buf = make([]byte, 19)
	buf[0] = 0xff
	buf[1] = 0xee
	buf[2] = code
	ts, _ := time.Now().MarshalBinary()
	copy(buf[4:], ts)
	conn.Write(buf)
}

func randMinArray() []byte {
	alen := rand.Intn(250)
	return randArray(alen + 6)
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

func makeDbcHello(data byte, secret []byte) []byte {
	randLen := rand.Int() % DPH_LEN1 // 8bit
	buf := randArray(randLen + DPH_P2)
	pos, sKey, hKey := extractKeys(secret)

	// actually f is uint16
	f := (randLen << 8) | int(data)
	f = (f + sKey) % DPH_MOD
	binary.BigEndian.PutUint16(buf[pos:pos+2], uint16(f))

	sum := siphash.Hash(hKey, calculateTimeCounter(false)[0], buf[:DPH_LEN1])
	binary.BigEndian.PutUint64(buf[DPH_LEN1:DPH_P2], sum)
	return buf
}

func verifyDbcHello(buf []byte, secret []byte, tc []uint64) (trusted bool, data, len2 byte) {
	pos, sKey, hKey := extractKeys(secret)
	p1 := buf[:DPH_LEN1]

	var sum, cltSum uint64
	cltSum = binary.BigEndian.Uint64(buf[DPH_LEN1:DPH_P2])

	for i := 0; !trusted && i < len(tc); i++ {
		sum = siphash.Hash(hKey, tc[i], p1)
		trusted = cltSum == sum
	}

	if !trusted {
		return
	}

	z := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
	z = (z - sKey + DPH_MOD) % DPH_MOD
	len2, data = byte(z>>8), byte(z&0xff)
	return
}

//
//
//
type msgWriter struct {
	buf *bytes.Buffer
	tmp []byte
}

func newMsgWriter() *msgWriter {
	return &msgWriter{
		buf: new(bytes.Buffer),
		tmp: make([]byte, 2),
	}
}

func (w *msgWriter) WriteL1Msg(msg []byte) *msgWriter {
	w.buf.WriteByte(byte(len(msg)))
	w.buf.Write(msg)
	return w
}

func (w *msgWriter) WriteL2Msg(msg []byte) *msgWriter {
	binary.BigEndian.PutUint16(w.tmp, uint16(len(msg)))
	w.buf.Write(w.tmp)
	w.buf.Write(msg)
	return w
}

// no length specified
func (w *msgWriter) WriteMsg(msg []byte) *msgWriter {
	w.buf.Write(msg)
	return w
}

func (w *msgWriter) WriteTo(d io.Writer) (err error) {
	_, err = w.buf.WriteTo(d)
	w.buf.Reset()
	return
}
