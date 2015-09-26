// +build !race

package tunnel

import (
	log "github.com/Lafeng/deblocus/golang/glog"
	"sync/atomic"
	"testing"
	"time"
)

const (
	acquirer = 66
	tmo      = time.Millisecond * 200
)

var cnt1 int32
var cnt2 int32

func Test_sema(tt *testing.T) {
	t := newTest(tt)
	s := NewSemaphore(false)
	for i := 0; i < acquirer; i++ {
		go acquire(s, i, tt)
	}
	_sleep()

	s.notifyAll() // whole observers begin releasing
	_sleep()      // all done
	t.Assert(cnt1 == acquirer && s.observer == 0).
		Fatalf("observer=%d waked=%d chan.len=%d", s.observer, cnt1, cap(s.bus))

	go acquire(s, 100, tt) // new observer No.100, will be timeout
	_sleep()
	t.Assert(cnt1 == acquirer && s.observer == 1).
		Fatalf("observer=%d waked=%d chan.len=%d", s.observer, cnt1, cap(s.bus))
}

func Test_sema_timeout(tt *testing.T) {
	t := newTest(tt)
	s := NewSemaphore(false)
	for i := 0; i < acquirer; i++ {
		go acquire(s, i, tt)
	}
	_sleep()
	_sleep() // make timeout

	// acquirer+1, include the No.100 acquirer
	t.Assert(cnt2 == acquirer+1 && s.observer == 0).
		Fatalf("observer=%d waked=%d chan.len=%d", s.observer, cnt2, cap(s.bus))
}

func acquire(s *semaphore, id int, t *testing.T) {
	if s.acquire(tmo + time.Millisecond*50) {
		atomic.AddInt32(&cnt1, 1)
		if log.V(3) {
			t.Log("\tacquired", id)
		}
	} else {
		atomic.AddInt32(&cnt2, 1)
		if log.V(3) {
			t.Log("\tacquired timeout", id)
		}
	}
}

func _sleep() {
	time.Sleep(tmo)
}
