package tunnel

import (
	"encoding/binary"
	"fmt"
	ex "github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	FRAME_ACTION_CLOSE    = 0
	FRAME_ACTION_OPEN     = 1
	FRAME_ACTION_OPEN_N   = 2
	FRAME_ACTION_OPEN_Y   = 3
	FRAME_ACTION_DATA     = 4
	FRAME_ACTION_PING     = 5
	FRAME_ACTION_PONG     = 6
	FRAME_ACTION_SLOWDOWN = 0xff
	FRAME_MAX_LEN         = 0xffff
	FRAME_HEADER_LEN      = 5
	FRAME_OPEN_TIMEOUT    = time.Second * 30
	MUX_PENDING_CLOSE     = -1
	MUX_CLOSED            = -2
	ERR_PING_TIMEOUT      = 0xe
	ERR_NEW_PING          = 0xf
	ERR_UNKNOWN           = 0x0
)

var (
	SID_SEQ uint32
	seqLock sync.Locker = new(sync.Mutex)
)

type edgeConn struct {
	conn   net.Conn
	ready  chan byte // peer status
	key    string
	dest   string
	status byte
}

func (e *edgeConn) getTarget() string {
	if e.dest != NULL {
		return e.dest
	} else {
		return e.conn.RemoteAddr().String()
	}
}

type idler struct {
	enabled  bool
	waiting  bool
	interval time.Duration
}

func NewIdler(interval int, isClient bool) *idler {
	if interval > 300 || interval < 30 {
		interval = DT_PING_INTERVAL
	}
	i := &idler{interval: time.Second * time.Duration(interval)}
	if isClient {
		i.interval *= 2
	}
	i.enabled = i.interval > 0
	return i
}

func (i *idler) newRound(tun *Conn) {
	if i.enabled {
		if i.waiting {
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
	//i.lastPing = time.Now().Unix()
	i.waiting = true
	buf := make([]byte, FRAME_HEADER_LEN)
	_frame(buf, FRAME_ACTION_PING, 0, nil)
	return tunWrite1(tun, buf)
}

func (i *idler) pong(tun *Conn) error {
	buf := make([]byte, FRAME_HEADER_LEN)
	_frame(buf, FRAME_ACTION_PONG, 0, nil)
	return tunWrite1(tun, buf)
}

func (i *idler) verify() (r bool) {
	r = i.waiting
	if i.waiting {
		i.waiting = false
	}
	return
}

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

func closeUi8(ch chan byte) {
	defer func() { _ = recover() }()
	close(ch)
}

type multiplexer struct {
	isClient bool
	pool     *ConnPool
	registry map[string]*edgeConn
	closed   map[string]bool
	cLock    sync.Locker
	queue    *queue
	mode     string
	status   int
}

func NewClientMultiplexer() *multiplexer {
	m := &multiplexer{
		isClient: true,
		pool:     NewConnPool(),
		registry: make(map[string]*edgeConn),
		closed:   make(map[string]bool),
		cLock:    new(sync.Mutex),
		mode:     "CLT",
	}
	m.queue = NewQueue(m)
	go m.queue.Listen()
	return m
}

func NewServerMultiplexer() *multiplexer {
	m := &multiplexer{
		registry: make(map[string]*edgeConn),
		closed:   make(map[string]bool),
		cLock:    new(sync.RWMutex),
		mode:     "SVR",
	}
	m.queue = NewQueue(m)
	go m.queue.Listen()
	return m
}

func (p *multiplexer) destroy() {
	defer func() {
		if !ex.CatchException(recover()) {
			p.status = MUX_CLOSED
		}
	}()
	p.cLock.Lock()
	defer p.cLock.Unlock()
	// will not send evt_dt_closed while pending_close was indicated
	p.status = MUX_PENDING_CLOSE
	p.pool.destroy()
	for _, v := range p.registry {
		SafeClose(v.conn)
	}
	p.queue.status = MUX_CLOSED
	p.queue.cond.Broadcast() // destroy queue
}

func (p *multiplexer) registerEdge(key string, conn net.Conn) {
	p.cLock.Lock()
	defer p.cLock.Unlock()
	p.registry[key] = &edgeConn{conn: conn, key: key}
}

func (p *multiplexer) registerEdgeWithDest(key string, conn net.Conn, destination string) {
	p.cLock.Lock()
	defer p.cLock.Unlock()
	p.registry[key] = &edgeConn{
		conn:  conn,
		ready: make(chan byte, 1),
		key:   key,
		dest:  destination,
	}
}

// active-close: deny deliveries from queue to edge
// passive-close: close in queue loop, then call back here.
func (p *multiplexer) unregisterEdge(key string, isPasv bool) (edge *edgeConn) {
	p.cLock.Lock()
	defer p.cLock.Unlock()
	if isPasv {
		p.closed[key] = true
	}
	edge = p.registry[key]
	if edge != nil {
		delete(p.registry, key)
		if edge.ready != nil {
			closeUi8(edge.ready)
		}
	}
	return
}

// check if closed passively
func (p *multiplexer) ckeckClosed(key string) bool {
	p.cLock.Lock()
	defer p.cLock.Unlock()
	t := p.closed[key]
	if t {
		delete(p.closed, key)
	}
	return t
}

func (p *multiplexer) getRegistered(key string) *edgeConn {
	p.cLock.Lock()
	defer p.cLock.Unlock()
	return p.registry[key]
}

func (p *multiplexer) HandleRequest(client net.Conn, target string) {
	sid := _nextSID()
	if log.V(1) {
		log.Infof("Socks5-> %s from=%s sid=%d\n", target, ipAddr(client.RemoteAddr()), sid)
	}
	tun := p.pool.Select()
	ThrowIf(tun == nil, "No tun to deliveries request")
	key := p.tunKey(tun, sid)
	defer p.unregisterEdge(key, false)
	p.registerEdgeWithDest(key, client, target)
	p.copyToTun(client, tun, key, sid, target)
}

func (p *multiplexer) cleanupOfTun(tun *Conn) {
	p.pool.Remove(tun)
	p.cLock.Lock()
	defer p.cLock.Unlock()
	var prefix = tun.identifier
	for k, v := range p.registry {
		if strings.HasPrefix(k, prefix) {
			SafeClose(v.conn)
			delete(p.registry, k)
		}
	}
}

func (p *multiplexer) onTunDisconnected(tun *Conn, handler event_handler) {
	p.cleanupOfTun(tun)
	if handler != nil && p.status >= 0 {
		handler(evt_dt_closed, tun)
	}
}

// TODO notify peer to slow down when queue increased too fast
func (p *multiplexer) Listen(tun *Conn, handler event_handler, interval int) {
	if p.isClient {
		tun.priority = &TSPriority{0, 1e9}
		p.pool.Push(tun)
		defer p.onTunDisconnected(tun, handler)
	}
	tun.SetSockOpt(1, 0, 0)
	var (
		frm        *frame
		header     = make([]byte, FRAME_HEADER_LEN)
		nr         int
		er         error
		now        int64
		lastActive int64 = time.Now().Unix()
		idle             = NewIdler(interval, p.isClient)
	)
	for {
		idle.newRound(tun)
		nr, er = io.ReadFull(tun, header)
		if nr == FRAME_HEADER_LEN {
			frm = _parseFrameHeader(header)
			if frm.length > 0 {
				nr, er = io.ReadFull(tun, frm.data)
			}
			//			if log.V(5) {
			//				log.Infoln(p.mode, "RECV", frm)
			//			}
		}
		if er != nil {
			switch idle.consumeError(er) {
			case ERR_NEW_PING:
				if idle.ping(tun) == nil {
					continue
				}
			case ERR_PING_TIMEOUT:
				log.Errorln("Peer was unresponsive and then close tun", tun.identifier)
			default:
				log.Errorln("Read tunnel", tun.identifier, er)
			}
			return // error, abandon tunnel
		}
		key := p.tunKey(tun, frm.sid)

		switch frm.action {
		case FRAME_ACTION_CLOSE:
			if log.V(3) {
				log.Infoln(p.mode, "recv CLOSE by peer. key:", key)
			}
			if edge := p.unregisterEdge(key, true); edge != nil {
				frm.conn = edge
				p.queue.push(frm)
			}
		case FRAME_ACTION_DATA:
			edge := p.getRegistered(key)
			if edge == nil {
				if log.V(2) {
					log.Warningln("peer try send data to an unexisted socket. key:", key, frm)
				}
				// so need to send close for notify peer.
				_frame(header, FRAME_ACTION_CLOSE, frm.sid, nil)
				if tunWrite1(tun, header) != nil {
					return
				}
			} else {
				frm.conn = edge
				p.queue.push(frm)
			}
		case FRAME_ACTION_OPEN:
			go p.openEgress(frm, key, tun)
		case FRAME_ACTION_OPEN_N, FRAME_ACTION_OPEN_Y:
			edge := p.getRegistered(key)
			if edge == nil {
				if log.V(2) {
					log.Warningln("peer try send OPEN to an unexisted socket. key:", key, frm)
				}
			} else {
				if log.V(3) {
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

func (p *multiplexer) tunKey(tun *Conn, sid uint16) string {
	if tun.identifier != NULL {
		return tun.identifier + "_" + strconv.FormatUint(uint64(sid), 10)
	} else {
		return fmt.Sprintf("%s_%s_%d", tun.LocalAddr(), tun.RemoteAddr(), sid)
	}
}

func (p *multiplexer) openEgress(frm *frame, key string, tun *Conn) {
	defer func() {
		ex.CatchException(recover())
	}()
	var (
		dstConn net.Conn
		err     error
		target  = string(frm.data)
	)
	dstConn, err = net.DialTimeout("tcp", target, FRAME_OPEN_TIMEOUT/3)
	frm.length = 0
	if err != nil {
		log.Errorf("Cannot connect to [%s] for %s error: %s\n", target, key, err)
		frm.action = FRAME_ACTION_OPEN_N
		tunWrite2(tun, frm)
	} else {
		p.registerEdge(key, dstConn)
		dstConn.SetReadDeadline(ZERO_TIME)
		if log.V(3) {
			log.Infoln("OPEN_Y", target, "established for key:", key)
		}
		frm.action = FRAME_ACTION_OPEN_Y
		if tunWrite2(tun, frm) == nil {
			p.copyToTun(dstConn, tun, key, frm.sid, NULL)
		} else {
			SafeClose(dstConn)
		}
	}
}

func (p *multiplexer) copyToTun(src net.Conn, tun *Conn, key string, sid uint16, target string) {
	var (
		buf = make([]byte, FRAME_MAX_LEN)
		nr  int
		er  error
	)
	defer func() {
		if !p.ckeckClosed(key) { // only proactive mode could send close
			_frame(buf, FRAME_ACTION_CLOSE, sid, nil)
			tunWrite1(tun, buf[:FRAME_HEADER_LEN])
		}
		// who read, who close
		// if closed passively, there is second close
		SafeClose(src)
	}()
	if target != NULL { // for client:
		// new connection must send OPEN first.
		_len := _frame(buf, FRAME_ACTION_OPEN, sid, []byte(target))
		if tunWrite1(tun, buf[:_len]) != nil {
			SafeClose(tun)
			return
		}
		var (
			edge = p.getRegistered(key)
			code byte
		)
		select {
		case code = <-edge.ready:
		case <-time.After(FRAME_OPEN_TIMEOUT):
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

func tunWrite1(tun *Conn, buf []byte) error {
	nr := len(buf)
	nw, err := tun.Write(buf)
	if nr != nw || err != nil {
		log.Warningf("Write tun(%s) error(%v) when sending buf.len=%d\n", tun.sign(), err, nr)
		SafeClose(tun)
		return err
	}
	return nil
}

func tunWrite2(tun *Conn, frm *frame) error {
	nw, err := tun.Write(frm.toNewBuffer())
	nr := int(frm.length) + FRAME_HEADER_LEN
	if nr != nw || err != nil {
		log.Warningf("Write tun(%s) error(%v) when sending %s\n", tun.sign(), err, frm)
		SafeClose(tun)
		return err
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
