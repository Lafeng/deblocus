package tunnel

import (
	"container/list"
	"fmt"
	log "github.com/spance/deblocus/golang/glog"
	"sync"
)

type queue struct {
	buffer *list.List
	lock   sync.Locker
	cond   *sync.Cond
	mux    *multiplexer
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
		}
		item := q.buffer.Front()
		q.buffer.Remove(item)
		q.lock.Unlock()
		// send
		var frm *frame = item.Value.(*frame)
		err := sendFrame(frm)
		if err {
			q.mux.unregisterConn(frm.conn.key, false)
		}
	}
}

// TODO should clean all queueing frames of conn that already has error occurred
func sendFrame(frm *frame) bool {
	dst := frm.conn.conn
	if frm.action == FRAME_ACTION_CLOSE {
		if log.V(5) {
			fmt.Printf("perform close by frame_action, link->%s %s\n", frm.conn.getTarget(), frm)
		}
	} else {
		if log.V(6) {
			fmt.Println("send", frm)
		}
		nw, ew := dst.Write(frm.data)
		if nw == int(frm.length) && ew == nil {
			return false
		}
		log.Warningf("Write edgeConn error. link->%s %s %s\n", frm.conn.getTarget(), frm, ew)
	}
	SafeClose(dst)
	return true
}
