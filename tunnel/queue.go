package tunnel

import (
	"container/list"
	log "github.com/spance/deblocus/golang/glog"
	"net"
	"sync"
	"time"
)

type queue struct {
	buffer *list.List
	lock   sync.Locker
	cond   *sync.Cond
	mux    *multiplexer
	status int
}

func NewQueue(m *multiplexer) *queue {
	q := &queue{
		buffer: list.New(),
		lock:   new(sync.Mutex),
		mux:    m,
	}
	q.cond = sync.NewCond(q.lock)
	return q
}

func (q *queue) push(frm *frame) {
	q.lock.Lock()
	defer q.cond.Signal()
	defer q.lock.Unlock()
	// push
	q.buffer.PushBack(frm)
}

func (q *queue) Listen() {
	for {
		q.lock.Lock()
		for q.buffer.Len() <= 0 {
			q.cond.Wait()
			// MUX_CLOSED: exit loop
			if q.status < 0 {
				q.buffer.Init()
				q.buffer = nil
				q.lock.Unlock()
				return
			}
		}
		item := q.buffer.Front()
		q.buffer.Remove(item)
		q.lock.Unlock()
		// send
		var frm *frame = item.Value.(*frame)
		closed, err := sendFrame(frm)
		if closed {
			q.mux.unregisterEdge(frm.conn.key, false)
		}
		if err {
			q.cleanOfConn(frm.conn.conn)
		}
	}
}

func (q *queue) cleanOfConn(conn net.Conn) {
	q.lock.Lock()
	defer q.lock.Unlock()
	for cur := q.buffer.Front(); cur != nil; cur = cur.Next() {
		if cur.Value == conn {
			q.buffer.Remove(cur)
		}
	}
}

func sendFrame(frm *frame) (closed, err bool) {
	dst := frm.conn.conn
	if frm.action == FRAME_ACTION_CLOSE {
		if log.V(4) {
			log.Infof("perform close(%s) by peer\n", frm.conn.getTarget())
		}
	} else {
		if log.V(5) {
			log.Infoln("SEND queue", frm)
		}
		dst.SetWriteDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
		nw, ew := dst.Write(frm.data)
		if nw == int(frm.length) && ew == nil {
			return
		}
		err = true
		log.Warningf("Write edge(%s) error(%v). %s\n", frm.conn.getTarget(), ew, frm)
	}
	closed = true
	SafeClose(dst)
	return
}
