package tunnel

import (
	"container/list"
	ex "github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	TCP_CLOSE_R uint8 = 1
	TCP_CLOSE_W uint8 = 1 << 1
	TCP_CLOSED        = TCP_CLOSE_R | TCP_CLOSE_W
)
const (
	// close code
	CLOSED_FORCE = iota
	CLOSED_WRITE
	CLOSED_BY_ERR
)

const (
	TICKER_INTERVAL = time.Second * 15
)

type edgeConn struct {
	mux      *multiplexer
	conn     net.Conn
	ready    chan byte // peer status
	key      string
	dest     string
	queue    *equeue
	positive bool // positively open
	closed   uint8
}

func (e *edgeConn) getTarget() string {
	if e.dest != NULL {
		return e.dest
	} else {
		return e.conn.RemoteAddr().String()
	}
}

func (e *edgeConn) deliver(frm *frame) {
	frm.conn = e
	e.queue._push(frm)
}

// ------------------------------
// EgressRouter
// ------------------------------
type egressRouter struct {
	lock     *sync.RWMutex
	mux      *multiplexer
	registry map[string]*edgeConn
	ticker   *time.Ticker
}

func newEgressRouter(mux *multiplexer) *egressRouter {
	r := &egressRouter{
		lock:     new(sync.RWMutex),
		mux:      mux,
		registry: make(map[string]*edgeConn),
		ticker:   time.NewTicker(TICKER_INTERVAL),
	}
	go r.cleanTask()
	return r
}

func (r *egressRouter) getRegistered(key string) *edgeConn {
	r.lock.RLock()
	var e = r.registry[key]
	r.lock.RUnlock()
	if e != nil && e.closed >= TCP_CLOSED {
		// clean when getting
		r.lock.Lock()
		delete(r.registry, key)
		r.lock.Unlock()
		return nil
	}
	return e
}

func (r *egressRouter) clean() {
	defer func() {
		ex.CatchException(recover())
	}()
	r.lock.Lock()
	defer r.lock.Unlock()
	for k, e := range r.registry {
		// call conn.LocalAddr will give rise to checking fd.
		if e == nil || e.closed >= TCP_CLOSED || e.conn.LocalAddr() == nil {
			delete(r.registry, k)
		}
	}
}

func (r *egressRouter) register(key, destination string, conn net.Conn) *edgeConn {
	r.lock.Lock()
	defer r.lock.Unlock()
	var edge = r.registry[key]
	if edge == nil {
		edge = newEdgeConn(r.mux, key, destination, conn)
		r.registry[key] = edge
	}
	return edge
}

// destroy whole router
func (r *egressRouter) destroy() {
	r.lock.Lock()
	defer r.lock.Unlock()
	var frm = &frame{action: FRAME_ACTION_CLOSE}
	for _, e := range r.registry {
		e.queue._push(frm) // wakeup and self-exiting
	}
	r.stopCleanTask()
	r.registry = nil
}

// remove edges (with queues) were related to the tun
func (r *egressRouter) cleanOfTun(tun *Conn) {
	r.lock.Lock()
	defer r.lock.Unlock()
	var prefix = tun.identifier
	var frm = &frame{action: FRAME_ACTION_CLOSE}
	for k, e := range r.registry {
		if strings.HasPrefix(k, prefix) {
			e.queue._push(frm)
			delete(r.registry, k)
		}
	}
}

func (r *egressRouter) cleanTask() {
	for _ = range r.ticker.C {
		r.clean()
	}
}

func (r *egressRouter) stopCleanTask() {
	r.ticker.Stop()
}

// -------------------------------
// Equeue
// -------------------------------
type equeue struct {
	edge   *edgeConn
	lock   sync.Locker
	cond   *sync.Cond
	buffer *list.List
}

func newEdgeConn(mux *multiplexer, key, destination string, conn net.Conn) *edgeConn {
	var edge = &edgeConn{
		mux:  mux,
		conn: conn,
		key:  key,
		dest: destination,
	}
	if mux.isClient {
		edge.ready = make(chan byte, 1)
	}
	l := new(sync.Mutex)
	q := &equeue{
		edge:   edge,
		lock:   l,
		cond:   sync.NewCond(l),
		buffer: list.New(),
	}
	edge.queue = q
	go q.sendLoop()
	return edge
}

func (q *equeue) _push(frm *frame) {
	q.lock.Lock()
	defer q.cond.Signal()
	defer q.lock.Unlock()
	// push
	q.buffer.PushBack(frm)
}

func (q *equeue) sendLoop() {
	for {
		q.lock.Lock()
		for q.buffer.Len() <= 0 {
			q.cond.Wait()
		}
		item := q.buffer.Front()
		q.buffer.Remove(item)
		q.lock.Unlock()
		// send
		var frm *frame = item.Value.(*frame)
		switch frm.action {
		case FRAME_ACTION_CLOSE:
			q._close(true, CLOSED_FORCE)
			return
		case FRAME_ACTION_CLOSE_W:
			q._close(false, CLOSED_WRITE)
			return
		default:
			werr := sendFrame(frm)
			if werr {
				if q.edge.closed&TCP_CLOSE_W == 0 { // only positively closed can notify peer
					frm.length = 0
					frm.action = FRAME_ACTION_CLOSE_R
					edge := q.edge
					edge.closed |= TCP_CLOSE_W
					tun := edge.mux.pool.Select()
					tunWrite2(tun, frm)
				}
				q._close(true, CLOSED_BY_ERR)
				return
			}
		}
	}
}

// close for ending of queued task
func (q *equeue) _close(force bool, close_code uint) {
	q.lock.Lock()
	defer q.lock.Unlock()
	e := q.edge
	if log.V(4) {
		switch close_code {
		case CLOSED_BY_ERR:
			log.Infoln("terminate", e.dest)
		case CLOSED_FORCE:
			log.Infoln("close", e.dest)
		case CLOSED_WRITE:
			log.Infof("closeW %s by peer\n", e.dest)
		}
	}
	q.buffer.Init()
	q.buffer = nil
	if force {
		e.closed = TCP_CLOSE_R | TCP_CLOSE_W
		SafeClose(e.conn)
	} else {
		closeW(e.conn)
	}
}

func sendFrame(frm *frame) (werr bool) {
	dst := frm.conn.conn
	if log.V(5) {
		log.Infoln("SEND queue", frm)
	}
	dst.SetWriteDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
	nw, ew := dst.Write(frm.data)
	if nw == int(frm.length) && ew == nil {
		return
	}
	werr = true
	// an error occured
	log.Warningf("Write edge(%s) error(%v). %s\n", frm.conn.getTarget(), ew, frm)
	return
}
