package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lafeng/deblocus/crypto"
	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/glog"
	"github.com/cloudflare/golibs/bytepool"
	"github.com/cloudflare/golibs/lrucache"
)

const (
	// frame action 8bit
	FRAME_ACTION_CLOSE         uint8 = 0x0
	FRAME_ACTION_CLOSE_R             = 0x1
	FRAME_ACTION_CLOSE_W             = 0x2
	FRAME_ACTION_OPEN                = 0x10
	FRAME_ACTION_OPEN_Y              = 0x11
	FRAME_ACTION_OPEN_N              = 0x12
	FRAME_ACTION_OPEN_DENIED         = 0x13
	FRAME_ACTION_SLOWDOWN            = 0x20
	FRAME_ACTION_DATA                = 0x21
	FRAME_ACTION_PING                = 0x30
	FRAME_ACTION_PONG                = 0x31
	FRAME_ACTION_TOKENS              = 0x40
	FRAME_ACTION_TOKEN_REQUEST       = 0x41
	FRAME_ACTION_TOKEN_REPLY         = 0x42
	FRAME_ACTION_DNS_REQUEST         = 0x51
	FRAME_ACTION_DNS_REPLY           = 0x52
)

const (
	FRAME_HEADER_LEN = 8
	FRAME_MAX_LEN    = 0xffff
)

const (
	MUX_PENDING_CLOSE int32 = -1
	MUX_CLOSED        int32 = -2
)

const (
	FAST_OPEN              = true
	FAST_OPEN_BUF_MAX_SIZE = 1 << 16 // 64k
)

const (
	WAITING_OPEN_TIMEOUT = time.Second * 5
	WRITE_TUN_TIMEOUT    = time.Second * 10
	READ_TMO_IN_FASTOPEN = time.Millisecond * 100
)

const (
	// idle error type
	ERR_PING_TIMEOUT = 0xe
	ERR_NEW_PING     = 0xf
	ERR_UNKNOWN      = 0x0
)

const sid_max uint32 = 0xffff

var (
	// [1, 0xfffe]
	sid_seq      uint32
	dialer       net.Dialer
	bytePoolOnce sync.Once
	bytePool     *bytepool.BytePool
)

var (
	ERR_TUN_NA        = ex.New("No tunnels are available")
	ERR_DATA_TAMPERED = ex.New("data tampered")
)

// --------------------
// event_handler
// --------------------
type event byte

const (
	evt_tokens = event(1)
)

type event_handler func(e event, msg ...interface{})

// --------------------
// idler
// --------------------
type idler struct {
	enabled      bool
	waiting      bool
	interval     time.Duration
	lastPing     int64
	sRtt, devRtt int64
}

func NewIdler(interval int, isClient bool) *idler {
	if interval > 0 && (interval > 600 || interval < 60) {
		interval = DT_PING_INTERVAL
	}
	i := &idler{
		interval: time.Second * time.Duration(interval),
		enabled:  interval > 0,
	}
	if isClient {
		delta := myRand.Int63n(int64(GENERAL_SO_TIMEOUT) * 2)
		i.interval -= time.Duration(delta)
	} else { // server ping will be behind
		i.interval += GENERAL_SO_TIMEOUT
	}
	return i
}

func (i *idler) newRound(tun *Conn) {
	if i.enabled {
		if i.waiting { // ping sent, waiting response
			tun.SetReadDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
		} else {
			tun.SetReadDeadline(time.Now().Add(i.interval))
		}
	} /* else {
		tun.SetReadDeadline(ZERO_TIME)
	} */
}

func (i *idler) consumeError(err error) uint {
	if i.enabled && IsTimeout(err) {
		if i.waiting {
			return ERR_PING_TIMEOUT
		} else {
			return ERR_NEW_PING
		}
	}
	return ERR_UNKNOWN
}

func (i *idler) ping(tun *Conn) error {
	if i.enabled {
		i.waiting = true
		defer i.updateLast()
		buf := make([]byte, FRAME_HEADER_LEN)
		pack(buf, FRAME_ACTION_PING, 0, nil)
		return frameWriteBuffer(tun, buf)
	}
	return nil
}

func (i *idler) pong(tun *Conn) error {
	if i.enabled {
		buf := make([]byte, FRAME_HEADER_LEN)
		pack(buf, FRAME_ACTION_PONG, 0, nil)
		return frameWriteBuffer(tun, buf)
	}
	return nil
}

func (i *idler) verify() (r bool) {
	if i.waiting {
		i.waiting = false
		r = true
	}
	return
}

func (i *idler) updateLast() {
	i.lastPing = time.Now().UnixNano()
}

// ref: http://tools.ietf.org/html/rfc6298
// return srtt, devrtt in millisecond
func (i *idler) updateRtt() (int32, int32) {
	rtt := time.Now().UnixNano() - i.lastPing
	if i.devRtt != 0 {
		// DevRTT = (1-beta)*DevRTT + beta*(|R'-SRTT|)
		// simplify: devRtt with sign bit and β=0.5
		i.devRtt = i.devRtt>>1 + (rtt-i.sRtt)>>1
	} else {
		i.devRtt = rtt >> 3
	}
	if i.sRtt > 0 {
		// SRTT = (1-alpha)*SRTT + alpha*R'
		// Let α=0.25 because of the low sampling rate
		i.sRtt += (rtt - i.sRtt) >> 2
	} else {
		i.sRtt = rtt
	}
	return int32(i.sRtt / 1e6), int32(i.devRtt / 1e6)
}

// --------------------
// frame
// --------------------
type frame struct {
	action uint8
	sid    uint16
	length uint16
	data   []byte
	vary   byte
	conn   *edgeConn
}

func (f *frame) String() string {
	return fmt.Sprintf("Frame{sid=%d act=%x len=%d}", f.sid, f.action, f.length)
}

func (f *frame) free() {
	if len(f.data) > 0 {
		bytePool.Put(f.data)
		f.data = nil
	}
}

func initBytePool() {
	bytePool = new(bytepool.BytePool)
	bytePool.Init(time.Minute, 1<<20)
	dialer.Timeout = time.Second * 3
	dialer.DualStack = false
	//dialer.DualStack = determineDualStack()
}

// --------------------
// multiplexer
// --------------------
type multiplexer struct {
	isClient  bool
	pool      *ConnPool // similar to Link Aggregation
	router    *egressRouter
	role      string
	status    int32
	pingCnt   int32 // received ping count
	sRtt      int32
	filter    Filterable
	sLock     sync.Mutex
	blacklist *lrucache.LRUCache
}

func newServerMultiplexer() *multiplexer {
	bytePoolOnce.Do(initBytePool)
	m := &multiplexer{
		isClient: false,
		pool:     NewConnPool(),
		role:     "SVR",
	}
	m.router = newEgressRouter(m)
	return m
}

func newClientMultiplexer() *multiplexer {
	bytePoolOnce.Do(initBytePool)
	m := &multiplexer{
		isClient:  true,
		pool:      NewConnPool(),
		role:      "CLT",
		blacklist: lrucache.NewLRUCache(256),
	}
	m.router = newEgressRouter(m)
	return m
}

// destroy the whole mux
func (p *multiplexer) destroy() {
	// don't close repeatedly
	if atomic.LoadInt32(&p.status) < 0 {
		return
	}
	defer func() {
		if !ex.Catch(recover(), nil) {
			// no error occurred, then set closed
			atomic.StoreInt32(&p.status, MUX_CLOSED)
		}
	}()
	atomic.StoreInt32(&p.status, MUX_PENDING_CLOSE)
	p.sLock.Lock()
	defer p.sLock.Unlock()
	p.router.destroy() // destroy queue
	p.pool.destroy()
	p.router = nil
	p.pool = nil
}

// serve client request
func (p *multiplexer) HandleRequest(protocol string, req net.Conn, target string) int {
	// select a tunnel to serve client request
	if tun := p.pool.Select(); tun != nil {
		sid := next_sid()
		key := sessionKey(tun, sid)
		// ingress: register in router table
		// asynchronously transmit data from the tunnel to the edge connection
		edge := p.router.register(key, target, tun, req, true)
		if log.V(log.LV_REQ) {
			log.Infof("%s->[%s] from=%s sid=%d\n",
				protocol, target, ipAddr(req.RemoteAddr()), sid)
		}

		// egress: transmit data from the edge connection to the tunnel
		if ret := p.relay(edge, tun, sid); ret == FRAME_ACTION_OPEN_DENIED {
			return -1
		}
	} else {
		// offline
		log.Warningln(ERR_TUN_NA)
		time.Sleep(time.Second)
		SafeClose(req)
	}

	return 1
}

// destory resources associated with the tun
func (p *multiplexer) onTunDisconnected(tun *Conn, handler event_handler) {
	SafeClose(tun)
	if p.pool != nil {
		p.pool.Remove(tun)
	}
	if p.router != nil {
		p.router.cleanOfTun(tun)
	}
	// use finalizer to cleanup
	runtime.SetFinalizer(tun, cleanupConn)
}

// This thread will listen on the tunnel, and process ingress data packets,
// and route them to correct session.
// TODO notify peer to slow down when queue increased too fast
func (p *multiplexer) Listen(tun *Conn, handler event_handler, interval int) error {
	// set priority for selecting tunnel
	tun.priority = &TSPriority{0, 1e9}
	p.pool.Push(tun)
	defer p.onTunDisconnected(tun, handler)
	tun.SetSockOpt(1, 0, 1)

	var (
		header = make([]byte, FRAME_HEADER_LEN)
		idle   = NewIdler(interval, p.isClient)
		router = p.router
		nr     int
		er     error
		frm    *frame
		key    string
	)
	if !p.isClient {
		// the server needs to ping client at first
		// make client aware of using a valid token.
		idle.ping(tun)
	}
	for {
		idle.newRound(tun)
		// read frame header
		nr, er = io.ReadFull(tun, header)
		if nr == FRAME_HEADER_LEN {
			frm, er = parse_frame(header)
			if er == nil && len(frm.data) > 0 {
				// read all data and discard random tail
				nr, er = io.ReadFull(tun, frm.data)
				frm.data = frm.data[:frm.length]
			}
		}
		if er != nil {
			// Exit: shutdown
			if atomic.LoadInt32(&p.status) < 0 {
				// suppress disconnected message
				time.Sleep(time.Second)
				return nil
			}
			switch idle.consumeError(er) {
			case ERR_NEW_PING:
				if er = idle.ping(tun); er == nil {
					continue
				}
			case ERR_PING_TIMEOUT:
				er = ex.New("Peer was unresponsive then close")
			}
			// Exit: abandon this connection
			return er
		}
		// prepare the session key of the frame
		key = sessionKey(tun, frm.sid)

		switch frm.action {
		// stop egress
		case FRAME_ACTION_CLOSE_W:
			if edge, _ := router.getRegistered(key); edge != nil {
				edge.bitwiseCompareAndSet(TCP_CLOSE_W)
				edge.deliver(frm)
			}
		// stop ingress
		case FRAME_ACTION_CLOSE_R:
			if edge, _ := router.getRegistered(key); edge != nil {
				edge.bitwiseCompareAndSet(TCP_CLOSE_R)
				closeR(edge.conn)
			}

		case FRAME_ACTION_DATA:
			edge, pre := router.getRegistered(key)
			if edge != nil {
				// normally
				edge.deliver(frm)
			} else if pre {
				// in remoteOpen
				router.preDeliver(key, frm)
			} else {
				if log.V(log.LV_WARN) {
					log.Warningln("Peer sent data to an unexisted socket.", key, frm)
				}
				// notice peer to stop sending
				pack(header, FRAME_ACTION_CLOSE_R, frm.sid, nil)
				if er = frameWriteBuffer(tun, header); er != nil {
					return er
				}
			}

			// for c/s proxy, this only exist in server side
		case FRAME_ACTION_OPEN:
			router.preRegister(key)
			// ingress: connect to final destination
			go p.connectToDest(frm, key, tun)

		case FRAME_ACTION_OPEN_N, FRAME_ACTION_OPEN_Y, FRAME_ACTION_OPEN_DENIED:
			edge, _ := router.getRegistered(key)
			if edge != nil {
				if log.V(log.LV_ACT_FRM) {
					log.Infoln(p.role, "received OPEN_x", frm)
				}
				edge.sendThenClose(frm.action)
			} else {
				if log.V(log.LV_WARN) {
					log.Warningln("Peer sent OPEN_x to an unexisted socket.", key, frm)
				}
			}

		case FRAME_ACTION_PING:
			if er = idle.pong(tun); er == nil {
				atomic.AddInt32(&p.pingCnt, 1)
			} else { // reply pong failed
				return er
			}

		case FRAME_ACTION_PONG:
			if idle.verify() {
				if p.isClient && idle.lastPing > 0 {
					sRtt, devRtt := idle.updateRtt()
					atomic.StoreInt32(&p.sRtt, sRtt)
					if DEBUG {
						log.Infof("sRtt=%d devRtt=%d", sRtt, devRtt)
						if devRtt+(sRtt>>2) > sRtt {
							// restart ???
							log.Warningf("Network jitter sRtt=%d devRtt=%d", sRtt, devRtt)
						}
					}
				}
			} else {
				log.Warningln("Incorrect action_pong received")
			}

		case FRAME_ACTION_TOKENS:
			handler(evt_tokens, frm.data)

		default: // impossible
			return fmt.Errorf("Unrecognized %s", frm)
		}
		tun.Update()
	}
}

func sessionKey(tun *Conn, sid uint16) string {
	if tun.identifier != NULL {
		return tun.identifier + "." + strconv.FormatUint(uint64(sid), 10)
	} else {
		return fmt.Sprintf("%s_%s_%d", tun.LocalAddr(), tun.RemoteAddr(), sid)
	}
}

// Server: open a connection to destination by frame
// then transmit data of dest to the tunnel
func (p *multiplexer) connectToDest(frm *frame, key string, tun *Conn) {
	var (
		dstConn net.Conn
		err     error
		target  = string(frm.data)
		denied  = false
	)
	if p.filter != nil {
		// denyDest filter
		denied = p.filter.Filter(target)
	}
	if !denied {
		dstConn, err = dialer.Dial("tcp", target)
	}

	p.sLock.Lock()
	// check mux status to prevent mux.fields were cleaned
	if atomic.LoadInt32(&p.status) < 0 {
		p.sLock.Unlock()
		return
	}

	if err != nil || denied { // can't accept
		// remove it from router and clean buffer
		p.router.removePreRegistered(key)
		p.sLock.Unlock()

		if denied {
			frm.action = FRAME_ACTION_OPEN_DENIED
			log.Warningf("Denied request [%s] for %s\n", target, key)
		} else {
			frm.action = FRAME_ACTION_OPEN_N
			log.Warningf("Cannot connect to [%s] for %s error: %s\n", target, key, err)
		}
		frameWriteHead(tun, frm)

	} else { // accept and register really
		dstConn.SetReadDeadline(ZERO_TIME)
		var edge = p.router.register(key, target, tun, dstConn, false) // write edge
		p.sLock.Unlock()

		if log.V(log.LV_SVR_OPEN) {
			log.Infoln("OPEN", target, "for", key)
		}

		// notify peer
		frm.action = FRAME_ACTION_OPEN_Y
		if frameWriteHead(tun, frm) == nil {
			// ingress: transmit edge data to tunnel
			p.relay(edge, tun, frm.sid)
		} else {
			// send notice/open_y failed
			SafeClose(tun)
		}
	}
}

func (p *multiplexer) relay(edge *edgeConn, tun *Conn, sid uint16) (ret byte) {
	var (
		buf         = bytePool.Get(FRAME_MAX_LEN)
		destHost    = edge.dest[2:] // dest with a leading mark
		src         = edge.conn
		pushbackBuf []byte
		code        byte
	)
	defer func() {
		// actively close then notify peer
		if edge.bitwiseCompareAndSet(TCP_CLOSE_R) && code != FRAME_ACTION_OPEN_DENIED {
			pack(buf, FRAME_ACTION_CLOSE_W, sid, nil)
			go func() {
				// tell peer to closeW
				frameWriteBuffer(tun, buf[:FRAME_HEADER_LEN])
				bytePool.Put(buf)
			}()
		} else {
			bytePool.Put(buf)
		}

		// close operation by code
		switch code {
		case FRAME_ACTION_OPEN_Y:
			closeR(src)
		case FRAME_ACTION_OPEN_DENIED:
			ret = code
			if pushbackBuf != nil {
				pbConn := src.(*pushbackInputStream)
				pbConn.Unread(pushbackBuf)
			}
		default: // remote open failed
			SafeClose(src)
		}
	}()

	// for client
	if edge.active {
		// check blacklist
		if _, y := p.blacklist.GetNotStale(destHost); y {
			code = FRAME_ACTION_OPEN_DENIED
			if log.V(log.LV_REQ) {
				log.Infof("Request %s was denied", edge.dest)
			}
			return
		}
		// send destination to perform remoteOpen
		_len := pack(buf, FRAME_ACTION_OPEN, sid, []byte(destHost))
		if frameWriteBuffer(tun, buf[:_len]) != nil {
			SafeClose(tun)
			return
		}
	}

	// return true if the request must be aborted
	var checkOpenSignal = func(ptrRemoteOpen *bool, code byte) bool {
		switch code {
		case FRAME_ACTION_OPEN_Y:
			// remoteOpen finished
			*ptrRemoteOpen = false
			// recycle buffer
			pushbackBuf = nil
			return false

		case FRAME_ACTION_OPEN_DENIED:
			// update blacklist
			p.blacklist.Set(destHost, true, time.Now().Add(time.Hour))
			if log.V(log.LV_REQ) {
				log.Infof("Request %s was denied by remote", edge.dest)
			}

		case FRAME_ACTION_OPEN_N:
			if log.V(log.LV_REQ) {
				log.Infof("Remote open %s failed", edge.dest)
			}
		}
		return true
	}

	var (
		tn         int // total
		nr         int
		er         error
		remoteOpen = p.isClient
		dataBuf    = buf[FRAME_HEADER_LEN:]
	)

	for {
		if remoteOpen {
			if nr > 0 {
				// keep read data into pushbackBuf
				pushbackBuf = append(pushbackBuf, dataBuf[:nr]...)
			}

			if tn < FAST_OPEN_BUF_MAX_SIZE {
				// can send small data to tunnel while not sure the result of remote open
				select {
				case code = <-edge.ready: // received
					if checkOpenSignal(&remoteOpen, code) {
						return
					}
				default:
				}

			} else {
				// too many data was sent to tunnel then must wait for signal
				select {
				case code = <-edge.ready:
				case <-time.After(WAITING_OPEN_TIMEOUT):
					log.Errorf("Waiting open-signal sid=%d timeout for %s\n", sid, edge.dest)
				}
				// timeout or open-signal received
				if checkOpenSignal(&remoteOpen, code) {
					return
				}
			}

			if remoteOpen {
				// remoteOpening: use timeout to recheck remoteOpen state ASAP
				src.SetReadDeadline(time.Now().Add(READ_TMO_IN_FASTOPEN))
			} else { // remoteOpen has been finished
				// read forever
				src.SetReadDeadline(ZERO_TIME)
			}
		}

		nr, er = src.Read(dataBuf)
		if nr > 0 {
			tn += nr
			pack(buf, FRAME_ACTION_DATA, sid, uint16(nr))
			if frameWriteBuffer(tun, buf[:nr+FRAME_HEADER_LEN]) != nil {
				SafeClose(tun)
				return
			}
		}

		// timeout cause of rechecking then open-signal in remoteOpen
		if er != nil && !(remoteOpen && IsTimeout(er)) {
			if er != io.EOF && DEBUG {
				log.Infof("Read to the end of edge total=%d err=(%v)", tn, er)
			}
			return
		}
	}
}

// best to send message to peer in some critical cases
func (p *multiplexer) bestSend(data []byte, action_desc string) bool {
	var buf = make([]byte, FRAME_HEADER_LEN+len(data))
	pack(buf, FRAME_ACTION_TOKENS, 0, data)

	for i := 1; i <= 3; i++ {
		if atomic.LoadInt32(&p.status) < 0 /* MUX_CLOSED */ || p.pool == nil {
			log.Warningln("Abandon sending data of", action_desc)
			break
		}
		tun := p.pool.Select()
		if tun != nil {
			if frameWriteBuffer(tun, buf) == nil {
				return true
			}
		} else {
			time.Sleep(time.Millisecond * 200 * time.Duration(i))
		}
	}
	log.Warningln("failed to send data of", action_desc)
	return false
}

// frame writer
func frameWriteBuffer(tun *Conn, origin []byte) (err error) {
	// default timeout is 10s
	err = tun.SetWriteDeadline(time.Now().Add(WRITE_TUN_TIMEOUT))
	if err == nil {
		var nw int
		buf := frameTransform(origin)
		nw, err = tun.Write(buf)
		if nw != len(buf) || err != nil {
			idleLastR := time.Now().UnixNano() - tun.priority.last
			if IsTimeout(err) && idleLastR < int64(WRITE_TUN_TIMEOUT) {
				err = nil
			} else {
				log.Warningf("Write tun (%s) error (%v) buf.len=%d\n", tun.identifier, err, len(buf))
				SafeClose(tun)
			}
		}
	}
	return
}

// frame writer
func frameWriteHead(tun *Conn, frm *frame) (err error) {
	b := make([]byte, FRAME_HEADER_LEN)
	b[0] = frm.action
	binary.BigEndian.PutUint16(b[2:], frm.sid)
	b[4] = 0 // no body
	b[5] = 0
	return frameWriteBuffer(tun, b)
}

func frameTransform(buf []byte) []byte {
	theLen := len(buf)
	if theLen > 32 {
		buf[1] = 0
		crypto.SetHash16At6(buf)
		return buf
	} else {
		box := randArray(theLen + 256)
		copy(box, buf)
		box[1] = box[len(box)-1]
		crypto.SetHash16At6(box)
		return box[:theLen+int(box[1])]
	}
}

// unpack frame
func parse_frame(header []byte) (*frame, error) {
	f := &frame{
		action: header[0],
		vary:   header[1],
		sid:    binary.BigEndian.Uint16(header[2:]),
		length: binary.BigEndian.Uint16(header[4:]),
	}
	if crypto.VerifyHash16At6(header) {
		bodyLen := int(f.length) + int(f.vary)
		if bodyLen > 0 {
			f.data = bytePool.Get(bodyLen)
		}
		return f, nil
	}
	return nil, ERR_DATA_TAMPERED
}

// range: [1, sid_max)
func next_sid() uint16 {
	for {
		if sid := atomic.AddUint32(&sid_seq, 1); sid < sid_max {
			return uint16(sid)
		}
		if atomic.CompareAndSwapUint32(&sid_seq, sid_max, 1) {
			return 1
		}
	}
}

// 0 | 1 | 2-3 | 4-5
func pack(buf []byte, action byte, sid uint16, body_or_len interface{}) int {
	var _len uint16
	buf[0] = action
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:], sid)
	if body_or_len != nil {
		switch body_or_len.(type) {
		case []byte:
			body := body_or_len.([]byte)
			_len = uint16(len(body))
			copy(buf[FRAME_HEADER_LEN:], body)
		case uint16:
			_len = body_or_len.(uint16)
		default:
			panic("unknown body_or_len")
		}
		binary.BigEndian.PutUint16(buf[4:], _len)
	} else {
		buf[4] = 0
		buf[5] = 0
	}
	return int(_len) + FRAME_HEADER_LEN
}
