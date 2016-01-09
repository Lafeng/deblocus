package tunnel

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	_WS_READY  = 1
	_WS_CANCEL = 0xfe
	_WS_TMO    = 0xff
)

type timedWait struct {
	lock      *sync.Mutex
	signal    chan int32
	state     int32
	waiters   int32
	tmoResult bool
}

func NewTimedWait(timeoutResult bool) *timedWait {
	return &timedWait{
		signal:    make(chan int32),
		lock:      new(sync.Mutex),
		tmoResult: timeoutResult,
	}
}

// call await will join in a waiting-group
// until the lock holder has been woken up by signal or timeout
// others will use the state of waiting-group as result
func (s *timedWait) await(timeout time.Duration) bool {
	atomic.AddInt32(&s.waiters, 1)
	defer s.reset()
	s.lock.Lock()
	defer s.lock.Unlock()

	state := atomic.LoadInt32(&s.state)
	if state == 0 { // first lock holder
		select {
		case state = <-s.signal:
		case <-time.After(timeout):
			state = _WS_TMO
		}
		atomic.StoreInt32(&s.state, state)
	}

	if state == _WS_TMO {
		return s.tmoResult
	} else {
		return state == _WS_READY
	}
}

func (s *timedWait) notifyAll() {
	select {
	case s.signal <- _WS_READY:
	default:
	}
}

func (s *timedWait) clearAll() {
	select {
	case s.signal <- _WS_CANCEL:
	default:
	}
}

func (s *timedWait) reset() {
	w := atomic.AddInt32(&s.waiters, -1)
	if w <= 0 {
		atomic.StoreInt32(&s.state, 0)
		// clear chan buffer
		select {
		case <-s.signal:
		default:
		}
	}
}
