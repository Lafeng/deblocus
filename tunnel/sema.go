package tunnel

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type semaphore struct {
	bus      chan byte
	lock     sync.Locker
	observer int32
}

func NewSemaphore() *semaphore {
	return &semaphore{
		bus:  make(chan byte, 8),
		lock: new(sync.Mutex),
	}
}

func (s *semaphore) acquire(timeout time.Duration) bool {
	s.lock.Lock()
	observer := atomic.AddInt32(&s.observer, 1)
	if size := cap(s.bus); size < int(observer) {
		oldBus := s.bus
		s.bus = make(chan byte, size<<1)
		for i := 0; i < size; i++ {
			oldBus <- 0
		}
	}
	s.lock.Unlock()
	defer atomic.AddInt32(&s.observer, -1)
	for {
		select {
		case x := <-s.bus:
			if x == 0 {
				runtime.Gosched()
			} else {
				return true
			}
		case <-time.After(timeout):
			return false
		}
	}
}

func (s *semaphore) notifyAll() {
	var size int32
	s.lock.Lock()
	size = s.observer
	s.lock.Unlock()
	for ; size > 0; size-- {
		s.bus <- 1
	}
}
