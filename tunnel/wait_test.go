package tunnel

import (
	"sync/atomic"
	"testing"
	"time"
)

const (
	tmo = time.Millisecond * 400
)

var (
	cnt1     int32
	cnt2     int32
	acquirer int32 = 3200
)

func TestWait(tt *testing.T) {
	t := newTest(tt)
	s := NewTimedWait(false)

	for i := int32(0); i < acquirer; i++ {
		go acquire(s, i, tt)
	}
	_sleep()      // wait for dispatching goroutines, but can't timeout
	s.notifyAll() // all waiters should be woken
	_sleepUntilTimeout()

	if w, c1, c2 := atomic.LoadInt32(&s.waiters), atomic.LoadInt32(&cnt1), atomic.LoadInt32(&cnt2); 1 == 0 ||
		c1 != acquirer || w != 0 {
		t.Fatalf("1 waiters=%d cnt1=%d cnt2", w, c1, c2)
	}

	if state := atomic.LoadInt32(&s.state); state != 0 {
		t.Fatalf("state=%d", state)
	}

	go acquire(s, acquirer, tt) // new waiters No.100, will be timeout
	_sleep()
	if w, c1, c2 := atomic.LoadInt32(&s.waiters), atomic.LoadInt32(&cnt1), atomic.LoadInt32(&cnt2); 1 == 0 ||
		c1 != acquirer || w != 0 {
		t.Fatalf("2 waiters=%d cnt1=%d cnt2", w, c1, c2)
	}
}

func TestWaitTimeout(tt *testing.T) {
	t := newTest(tt)
	s := NewTimedWait(false)

	for i := int32(0); i < acquirer; i++ {
		go acquire(s, i, tt)
	}
	_sleepUntilTimeout()

	if state := atomic.LoadInt32(&s.state); state != 0 {
		t.Fatalf("state=%d", state)
	}

	// acquirer+1, include the No.100 acquirer
	if w, c1, c2 := atomic.LoadInt32(&s.waiters), atomic.LoadInt32(&cnt1), atomic.LoadInt32(&cnt2); 1 == 0 ||
		c2 != acquirer+1 || w != 0 {
		t.Fatalf("1 waiters=%d cnt1=%d cnt2", w, c1, c2)
	}
}

func acquire(s *timedWait, id int32, t *testing.T) {
	if s.await(tmo + time.Millisecond*50) {
		atomic.AddInt32(&cnt1, 1)
	} else {
		atomic.AddInt32(&cnt2, 1)
	}
}

func _sleep(m ...int) {
	time.Sleep(tmo - time.Millisecond*50)
}

func _sleepUntilTimeout() {
	time.Sleep(tmo * 2)
}
