package tunnel

import (
	"sort"
	"sync"
	"sync/atomic"

	log "github.com/Lafeng/deblocus/glog"
)

const SELECT_DECREASE = -1e5

type TSPriority struct {
	last int64
	rank int64
}

type ConnPool struct {
	pool sortableConns
	lock sync.Locker
}

func NewConnPool() *ConnPool {
	return &ConnPool{lock: new(sync.Mutex)}
}

type sortableConns []*Conn

func (h sortableConns) Len() int           { return len(h) }
func (h sortableConns) Less(i, j int) bool { return h[i].priority.rank > h[j].priority.rank } // reverse
func (h sortableConns) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *ConnPool) Push(x *Conn) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.pool = append(h.pool, x)
}

func (h *ConnPool) Remove(c *Conn) bool {
	h.lock.Lock()
	defer h.lock.Unlock()
	var (
		x int = -1
		n     = h.pool.Len()
	)
	for i := 0; i < n; i++ {
		if h.pool[i] == c {
			x = i
			break
		}
	}
	if x < 0 {
		return false
	}
	switch {
	case x == 0:
		h.pool = h.pool[1:]
	case x == n-1:
		h.pool = h.pool[:x]
	case x > 0 && x < n-1:
		copy(h.pool[x:], h.pool[x+1:])
		h.pool = h.pool[:n-1]
	}
	return true
}

func (h *ConnPool) Len() int {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h.pool.Len()
}

func (h *ConnPool) Select() *Conn {
	h.lock.Lock()
	defer h.lock.Unlock()
	if h.pool.Len() < 1 {
		return nil
	}
	sort.Sort(h.pool)
	if log.V(log.LV_TUN_SELECT) {
		log.Infoln("Selected tun", h.pool[0].LocalAddr())
	}
	selected := h.pool[0]
	atomic.AddInt64(&selected.priority.rank, SELECT_DECREASE)
	return selected
}

func (h *ConnPool) destroy() {
	h.lock.Lock()
	defer h.lock.Unlock()
	for _, c := range h.pool {
		SafeClose(c)
	}
	h.pool = nil
}
