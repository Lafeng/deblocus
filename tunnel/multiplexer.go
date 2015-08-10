package tunnel

import (
	"encoding/binary"
	"fmt"
	ex "github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	// frame action 8bit
	FRAME_ACTION_CLOSE = iota
	FRAME_ACTION_CLOSE_R
	FRAME_ACTION_CLOSE_W
	FRAME_ACTION_OPEN
	FRAME_ACTION_OPEN_N
	FRAME_ACTION_OPEN_Y
	FRAME_ACTION_DATA
	FRAME_ACTION_PING
	FRAME_ACTION_PONG
	FRAME_ACTION_SLOWDOWN = 0xff
)

const (
	WAITING_OPEN_TIMEOUT = GENERAL_SO_TIMEOUT * 2
	FRAME_HEADER_LEN     = 5
	FRAME_MAX_LEN        = 0xffff
	MUX_PENDING_CLOSE    = -1
	MUX_CLOSED           = -2
)

const (
	// idle error type
	ERR_PING_TIMEOUT = 0xe
	ERR_NEW_PING     = 0xf
	ERR_UNKNOWN      = 0x0
)

var (
	SID_SEQ uint32
	seqLock sync.Locker = new(sync.Mutex)
)

type idler struct {
	enabled  bool
	waiting  bool
	interval time.Duration
}

func NewIdler(interval int, isClient bool) *idler {
	if interval > 0 && (interval > 300 || interval < 30) {
		interval = DT_PING_INTERVAL
	}
	i := &idler{
		interval: time.Second * time.Duration(interval),
		enabled:  interval > 0,
	}
	if isClient {
		i.interval -= GENERAL_SO_TIMEOUT
	} else { // server ping will be behind
		i.interval += GENERAL_SO_TIMEOUT
	}
	i.interval += time.Duration(randomRange(int64(time.Second), int64(GENERAL_SO_TIMEOUT)))
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

func (i *idler) consumeError(er error) uint {
	if i.enabled {
		if netErr, y := er.(net.Error); y && netErr.Timeout() {
			if i.waiting {
				return ERR_PING_TIMEOUT
			} else {
				return ERR_NEW_PING
			}
		}
	}
	return ERR_UNKNOWN
}

func (i *idler) ping(tun *Conn) error {
	if i.enabled {
		i.waiting = true
		buf := make([]byte, FRAME_HEADER_LEN)
		_frame(buf, FRAME_ACTION_PING, 0, nil)
		return tunWrite1(tun, buf)
	}
	return nil
}

func (i *idler) pong(tun *Conn) error {
	if i.enabled {
		buf := make([]byte, FRAME_HEADER_LEN)
		_frame(buf, FRAME_ACTION_PONG, 0, nil)
		return tunWrite1(tun, buf)
	}
	return nil
}

func (i *idler) verify() (r bool) {
	r = i.waiting
	if i.waiting {
		i.waiting = false
	}
	return
}

// --------------------
// frame
// --------------------
type frame struct {
	action uint8
	sid    uint16
	length uint16
	data   []byte
	conn   *edgeConn
}

func (f *frame) String() string {
	return fmt.Sprintf("Frame{sid=%d act=%d len=%d}", f.sid, f.action, f.length)
}

func (f *frame) toNewBuffer() []byte {
	b := make([]byte, f.length+FRAME_HEADER_LEN)
	b[0] = f.action
	binary.BigEndian.PutUint16(b[1:], f.sid)
	binary.BigEndian.PutUint16(b[3:], f.length)
	if f.length > 0 {
		copy(b[FRAME_HEADER_LEN:], f.data)
	}
	return b
}

// --------------------
// multiplexer
// --------------------
type multiplexer struct {
	isClient bool
	pool     *ConnPool
	router   *egressRouter
	mode     string
	status   int
}

func NewClientMultiplexer() *multiplexer {
	m := &multiplexer{
		isClient: true,
		pool:     NewConnPool(),
		mode:     "CLT",
	}
	m.router = newEgressRouter(m)
	return m
}

func NewServerMultiplexer() *multiplexer {
	m := &multiplexer{mode: "SVR"}
	m.router = newEgressRouter(m)
	return m
}

// destroy each listener of all pooled tun, and destroy egress queues
func (p *multiplexer) destroy() {
	defer func() {
		if !ex.CatchException(recover()) {
			p.status = MUX_CLOSED
		}
	}()
	// will not send evt_dt_closed while pending_close was indicated
	p.status = MUX_PENDING_CLOSE
	p.router.destroy() // destroy queue
	p.pool.destroy()
}

func (p *multiplexer) HandleRequest(prot string, client net.Conn, target string) {
	sid := _nextSID()
	if log.V(1) {
		log.Infof("%s->[%s] from=%s sid=%d\n", prot, target, ipAddr(client.RemoteAddr()), sid)
	}
	tun := p.pool.Select()
	ThrowIf(tun == nil, "No tun to deliveries request")
	key := sessionKey(tun, sid)
	edge := p.router.register(key, target, tun, client, true) // write edge
	p.relay(edge, tun, sid)                                   // read edge
}

func (p *multiplexer) onTunDisconnected(tun *Conn, handler event_handler) {
	p.router.cleanOfTun(tun)
	if p.isClient {
		p.pool.Remove(tun)
	}
	if handler != nil && p.status >= 0 {
		handler(evt_dt_closed, tun)
	}
}

// TODO notify peer to slow down when queue increased too fast
func (p *multiplexer) Listen(tun *Conn, handler event_handler, interval int) {
	if p.isClient {
		tun.priority = &TSPriority{0, 1e9}
		p.pool.Push(tun)
	}
	defer p.onTunDisconnected(tun, handler)
	tun.SetSockOpt(1, 1, 0)
	var (
		header     = make([]byte, FRAME_HEADER_LEN)
		router     = p.router
		idle       = NewIdler(interval, p.isClient)
		lastActive = time.Now().Unix()
		nr         int
		er         error
		now        int64
		frm        *frame
		key        string
	)
	for {
		idle.newRound(tun)
		nr, er = io.ReadFull(tun, header)
		if nr == FRAME_HEADER_LEN {
			frm = _parseFrameHeader(header)
			if frm.length > 0 {
				nr, er = io.ReadFull(tun, frm.data)
			}
		}
		if er != nil {
			switch idle.consumeError(er) {
			case ERR_NEW_PING:
				if idle.ping(tun) == nil {
					continue
				}
			case ERR_PING_TIMEOUT:
				log.Errorln("Peer was unresponsive then close", tun.identifier)
			default:
				log.Errorln("Read tunnel", tun.identifier, er)
			}
			return // error, abandon tunnel
		}
		key = sessionKey(tun, frm.sid)

		switch frm.action {
		case FRAME_ACTION_CLOSE_W:
			if edge := router.getRegistered(key); edge != nil {
				edge.closed |= TCP_CLOSE_W
				edge.deliver(frm)
			}
		case FRAME_ACTION_CLOSE_R:
			if edge := router.getRegistered(key); edge != nil {
				edge.closed |= TCP_CLOSE_R
				closeR(edge.conn)
			}
		case FRAME_ACTION_DATA:
			edge := router.getRegistered(key)
			if edge == nil {
				if log.V(2) {
					log.Warningln("peer send data to an unexisted socket.", key, frm)
				}
				// trigger sending close to notice peer.
				_frame(header, FRAME_ACTION_CLOSE_R, frm.sid, nil)
				if tunWrite1(tun, header) != nil {
					return
				}
			} else {
				edge.deliver(frm)
			}
		case FRAME_ACTION_OPEN:
			go p.connectToDest(frm, key, tun)
		case FRAME_ACTION_OPEN_N, FRAME_ACTION_OPEN_Y:
			edge := router.getRegistered(key)
			if edge == nil {
				if log.V(2) {
					log.Warningln("peer send OPENx to an unexisted socket.", key, frm)
				}
			} else {
				if log.V(4) {
					if frm.action == FRAME_ACTION_OPEN_Y {
						log.Infoln(p.mode, "recv OPEN_Y", frm)
					} else {
						log.Infoln(p.mode, "recv OPEN_N", frm)
					}
				}
				edge.ready <- frm.action
				close(edge.ready)
			}
		case FRAME_ACTION_PING:
			if idle.pong(tun) != nil {
				return
			}
		case FRAME_ACTION_PONG:
			if !idle.verify() {
				log.Warningln("Incorrect action_pong received")
			}
		default:
			log.Errorln(p.mode, "Unrecognized", frm)
		}

		// prevent frequently calling, especially in high-speed transmitting.
		if now = time.Now().Unix(); (now-lastActive) > 2 && handler != nil {
			lastActive = now
			handler(evt_st_active, now)
		}
		if p.isClient {
			tun.Update()
		}
	}
}

func sessionKey(tun *Conn, sid uint16) string {
	if tun.identifier != NULL {
		return tun.identifier + "." + strconv.FormatUint(uint64(sid), 10)
	} else {
		return fmt.Sprintf("%s_%s_%d", tun.LocalAddr(), tun.RemoteAddr(), sid)
	}
}

func (p *multiplexer) connectToDest(frm *frame, key string, tun *Conn) {
	defer func() {
		ex.CatchException(recover())
	}()
	var (
		dstConn net.Conn
		err     error
		target  = string(frm.data)
	)
	dstConn, err = net.DialTimeout("tcp", target, GENERAL_SO_TIMEOUT)
	frm.length = 0
	if err != nil {
		log.Errorf("Cannot connect to [%s] for %s error: %s\n", target, key, err)
		frm.action = FRAME_ACTION_OPEN_N
		tunWrite2(tun, frm)
	} else {
		if log.V(1) {
			log.Infoln("OPEN", target, "for", key)
		}
		dstConn.SetReadDeadline(ZERO_TIME)
		edge := p.router.register(key, target, tun, dstConn, false) // write edge
		frm.action = FRAME_ACTION_OPEN_Y
		if tunWrite2(tun, frm) == nil {
			p.relay(edge, tun, frm.sid) // read edge
		} else { // send open_y failed
			SafeClose(tun)
		}
	}
}

func (p *multiplexer) relay(edge *edgeConn, tun *Conn, sid uint16) {
	var (
		buf  = make([]byte, FRAME_MAX_LEN)
		nr   int
		er   error
		code byte
		src  = edge.conn
	)
	defer func() {
		if edge.closed&TCP_CLOSE_R == 0 { // only positively
			_frame(buf, FRAME_ACTION_CLOSE_W, sid, nil)
			tunWrite1(tun, buf[:FRAME_HEADER_LEN]) // tell peer to closeW
			edge.closed |= TCP_CLOSE_R
		}
		closeR(src)
	}()
	if edge.positive { // for client:
		// new connection must send OPEN first.
		_len := _frame(buf, FRAME_ACTION_OPEN, sid, []byte(edge.dest))
		if tunWrite1(tun, buf[:_len]) != nil {
			SafeClose(tun)
			return
		}
		select {
		case code = <-edge.ready:
			edge.initEqueue() // client delayed starting queue
		case <-time.After(WAITING_OPEN_TIMEOUT):
			log.Errorf("waiting open-signal(sid=%d) timeout for %s\n", sid, edge.dest)
		}
		if code != FRAME_ACTION_OPEN_Y {
			return
		}
	}
	for {
		nr, er = src.Read(buf[FRAME_HEADER_LEN:])
		if nr > 0 {
			_frame(buf, FRAME_ACTION_DATA, sid, uint16(nr))
			nr += FRAME_HEADER_LEN
			if tunWrite1(tun, buf[:nr]) != nil {
				SafeClose(tun)
				return
			}
		}
		if er != nil {
			return
		}
	}
}

func tunWrite1(tun *Conn, buf []byte) (err error) {
	err = tun.SetWriteDeadline(time.Now().Add(GENERAL_SO_TIMEOUT * 2))
	if err != nil {
		return
	}
	var nr, nw int
	nr = len(buf)
	nw, err = tun.Write(buf)
	if nr != nw || err != nil {
		log.Warningf("Write tun(%s) error(%v) when sending buf.len=%d\n", tun.sign(), err, nr)
		SafeClose(tun)
		return
	}
	return nil
}

func tunWrite2(tun *Conn, frm *frame) (err error) {
	err = tun.SetWriteDeadline(time.Now().Add(GENERAL_SO_TIMEOUT * 2))
	if err != nil {
		return
	}
	var nr, nw int
	nr = int(frm.length) + FRAME_HEADER_LEN
	nw, err = tun.Write(frm.toNewBuffer())
	if nr != nw || err != nil {
		log.Warningf("Write tun(%s) error(%v) when sending %s\n", tun.sign(), err, frm)
		SafeClose(tun)
		return
	}
	return nil
}

func _nextSID() uint16 {
	seqLock.Lock()
	defer seqLock.Unlock()
	SID_SEQ += 1
	if SID_SEQ > 0xffff {
		SID_SEQ = 1
	}
	return uint16(SID_SEQ)
}

func _parseFrameHeader(header []byte) *frame {
	f := &frame{
		header[0],
		binary.BigEndian.Uint16(header[1:]),
		binary.BigEndian.Uint16(header[3:]),
		nil, nil,
	}
	if f.length > 0 {
		f.data = make([]byte, f.length)
	}
	return f
}

func _frame(buf []byte, action byte, sid uint16, body_or_len interface{}) int {
	var _len = FRAME_HEADER_LEN
	buf[0] = action
	binary.BigEndian.PutUint16(buf[1:], sid)
	if body_or_len != nil {
		switch body_or_len.(type) {
		case []byte:
			body := body_or_len.([]byte)
			_len += len(body)
			binary.BigEndian.PutUint16(buf[3:], uint16(len(body)))
			copy(buf[FRAME_HEADER_LEN:], body)
		case uint16:
			blen := body_or_len.(uint16)
			_len += int(blen)
			binary.BigEndian.PutUint16(buf[3:], blen)
		default:
			panic("unknown body_or_len")
		}
	} else {
		buf[3] = 0
		buf[4] = 0
	}
	return _len
}
