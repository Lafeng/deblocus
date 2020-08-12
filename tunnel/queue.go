package tunnel

import (
	"container/list"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ex "github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/glog"
)

const (
	TCP_CLOSE_R uint32 = 1
	TCP_CLOSE_W uint32 = 1 << 1
	TCP_CLOSED  uint32 = TCP_CLOSE_R | TCP_CLOSE_W
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
	mux    *multiplexer
	tun    *Conn
	conn   net.Conn
	ready  chan byte // peer status
	key    string
	dest   string
	queue  *equeue
	active bool // actively open
	closed uint32
}

func newEdgeConn(mux *multiplexer, key, dest string, tun *Conn, conn net.Conn) *edgeConn {
	var edge = &edgeConn{
		mux:  mux,
		tun:  tun,
		conn: conn,
		key:  key,
	}
	if mux.isClient {
		edge.ready = make(chan byte, 1)
		edge.dest = "<-" + dest
	} else {
		edge.dest = "->" + dest
	}
	return edge
}

func (e *edgeConn) deliver(frm *frame) {
	if e.queue != nil {
		frm.conn = e
		e.queue._push(frm)
	}
}

// greater than or equals b
func (e *edgeConn) closed_gte(b uint32) bool {
	return atomic.LoadUint32(&e.closed) >= b
}

// read and check the mask bit, if not set then set with mask
func (e *edgeConn) bitwiseCompareAndSet(mask uint32) bool {
	c := atomic.LoadUint32(&e.closed)
	if c&mask == 0 {
		return atomic.CompareAndSwapUint32(&e.closed, c, c|mask)
	}
	return false
}

// send msg to the ready chan then close it
func (e *edgeConn) sendThenClose(val uint8) {
	defer func() { // catch exception
		_ = recover()
	}()
	e.ready <- val
	close(e.ready)
}

// ------------------------------
// EgressRouter
// ------------------------------
type egressRouter struct {
	lock            *sync.RWMutex
	mux             *multiplexer
	registry        map[string]*edgeConn
	preRegistry     map[string]*list.List
	cleanerTicker   *time.Ticker
	stopCleanerChan chan bool
}

func newEgressRouter(mux *multiplexer) *egressRouter {
	r := &egressRouter{
		lock:            new(sync.RWMutex),
		mux:             mux,
		registry:        make(map[string]*edgeConn),
		cleanerTicker:   time.NewTicker(TICKER_INTERVAL),
		stopCleanerChan: make(chan bool, 1),
	}
	if !mux.isClient {
		r.preRegistry = make(map[string]*list.List)
	}
	go r.cleanTask()
	return r
}

func (r *egressRouter) preRegister(key string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.preRegistry[key] = list.New()
}

func (r *egressRouter) preDeliver(key string, f *frame) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if buffer := r.preRegistry[key]; buffer != nil {
		buffer.PushBack(f)
	}
}

func (r *egressRouter) removePreRegistered(key string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	delete(r.preRegistry, key)
}

func (r *egressRouter) getRegistered(key string) (e *edgeConn, preRegistered bool) {
	r.lock.RLock()
	e = r.registry[key]
	_, preRegistered = r.preRegistry[key]
	r.lock.RUnlock()
	if e != nil && e.closed_gte(TCP_CLOSED) {
		// clean when getting
		r.lock.Lock()
		delete(r.registry, key)
		r.lock.Unlock()
		return nil, false
	}
	return
}

func (r *egressRouter) clean() {
	defer func() {
		ex.Catch(recover(), nil)
	}()
	r.lock.Lock()
	defer r.lock.Unlock()
	for k, e := range r.registry {
		// call conn.LocalAddr will give rise to checking fd.
		if e == nil || e.closed_gte(TCP_CLOSED) || e.conn.LocalAddr() == nil {
			delete(r.registry, k)
		}
	}
}

func (r *egressRouter) register(key, destination string, tun *Conn, conn net.Conn, active bool) *edgeConn {
	r.lock.Lock()
	defer r.lock.Unlock()
	var edge = r.registry[key]
	if edge == nil {
		edge = newEdgeConn(r.mux, key, destination, tun, conn)
		edge.active = active
		edge.initEqueue()
		r.registry[key] = edge
	}
	if buffer := r.preRegistry[key]; buffer != nil {
		delete(r.preRegistry, key)
		edge.queue._push_all(buffer)
	}
	return edge
}

// destroy whole router
func (r *egressRouter) destroy() {
	r.lock.Lock()
	defer r.lock.Unlock()
	var frm = &frame{action: FRAME_ACTION_CLOSE}
	for _, e := range r.registry {
		if e.queue != nil {
			e.queue._push(frm) // wakeup and self-exiting
		}
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
			if e.queue != nil {
				e.queue._push(frm)
			} else {
				SafeClose(e.conn)
			}
			delete(r.registry, k)
		}
	}
}

func (r *egressRouter) cleanTask() {
	var (
		stopCh <-chan bool = r.stopCleanerChan
		runCh              = r.cleanerTicker.C
	)
	for {
		select {
		case s := <-stopCh:
			if s {
				return
			}
		case <-runCh:
			r.clean()
		}
	}
}

func (r *egressRouter) stopCleanTask() {
	r.stopCleanerChan <- true
	close(r.stopCleanerChan)
	r.cleanerTicker.Stop()
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

func (edge *edgeConn) initEqueue() *equeue {
	l := new(sync.Mutex)
	q := &equeue{
		edge:   edge,
		lock:   l,
		cond:   sync.NewCond(l),
		buffer: list.New(),
	}
	edge.queue = q
	go q.sendLoop()
	return q
}

func (q *equeue) _push(frm *frame) {
	q.lock.Lock()
	defer q.cond.Signal()
	defer q.lock.Unlock()
	// push
	if q.buffer != nil {
		q.buffer.PushBack(frm)
	} // else the queue was exited
}

func (q *equeue) _push_all(buffer *list.List) {
	q.lock.Lock()
	defer q.cond.Signal()
	defer q.lock.Unlock()
	// push
	if _list := q.buffer; _list != nil {
		for i, e := buffer.Len(), buffer.Front(); i > 0; i, e = i-1, e.Next() {
			f := e.Value.(*frame)
			f.conn = q.edge
			_list.PushBack(f)
		}
	} // else the queue was exited
}

func (q *equeue) sendLoop() {
	for {
		var buffer *list.List
		q.lock.Lock()
		for q.buffer.Len() <= 0 {
			q.cond.Wait()
		}
		buffer = q.buffer
		q.buffer = list.New()
		q.lock.Unlock()

		for item := buffer.Front(); item != nil; item = item.Next() {
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
					edge := q.edge
					if edge.bitwiseCompareAndSet(TCP_CLOSE_W) { // only actively closed can notify peer
						tun := edge.tun
						// may be a broken tun
						if tun == nil || tun.LocalAddr() == nil {
							tun = edge.mux.pool.Select()
						}
						if tun != nil {
							frm.action = FRAME_ACTION_CLOSE_R
							frameWriteHead(tun, frm)
						}
					}
					q._close(true, CLOSED_BY_ERR)
					frm.free()
					return
				} else {
					frm.free()
				}
			}
		}
	}
}

// close for ending of queued task
func (q *equeue) _close(force bool, close_code uint) {
	q.lock.Lock()
	defer q.lock.Unlock()
	e := q.edge
	if log.V(log.LV_ACT_FRM) {
		switch close_code {
		case CLOSED_BY_ERR:
			log.Infoln("Terminate", e.dest)
		case CLOSED_FORCE:
			log.Infoln("Close", e.dest)
		case CLOSED_WRITE:
			log.Infof("CloseWrite %s by peer\n", e.dest)
		}
	}

	for i, e := q.buffer.Len(), q.buffer.Front(); i > 0; i, e = i-1, e.Next() {
		f := e.Value.(*frame)
		if f != nil {
			f.free()
		}
	}

	q.buffer = nil
	if force {
		atomic.StoreUint32(&e.closed, TCP_CLOSED)
		SafeClose(e.conn)
	} else {
		closeW(e.conn)
	}
}

func sendFrame(frm *frame) bool {
	dst := frm.conn.conn
	if log.V(log.LV_DAT_FRM) {
		log.Infoln("SEND queue", frm)
	}
	dst.SetWriteDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
	nw, ew := dst.Write(frm.data)
	if nw == int(frm.length) && ew == nil {
		return false
	}
	// an error occured
	if log.V(log.LV_WARN_EDGE) {
		log.Warningf("Write edge (%s) error (%v) %s\n", frm.conn.dest, ew, frm)
	}
	return true
}
