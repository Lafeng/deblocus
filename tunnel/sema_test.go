package tunnel

import (
	log "github.com/Lafeng/deblocus/golang/glog"
	"sync/atomic"
	"testing"
	"time"
)

const (
	acquirer = 66
	tmo      = time.Second * 2
)

var cnt1 int32
var cnt2 int32

func Test_sema(t *testing.T) {
	s := NewSemaphore(false)
	for i := 0; i < acquirer; i++ {
		go acquire(s, i, t)
	}
	_sleep()
	s.notifyAll()
	_sleep()
	if cnt1 == acquirer && s.observer == 0 {
		t.Logf("observer=%d awake=%d chan.len=%d \n", s.observer, cnt1, cap(s.bus))
	} else {
		t.Errorf("observer=%d awake=%d chan.len=%d \n", s.observer, cnt1, cap(s.bus))
	}
}

func Test_sema2(t *testing.T) {
	s := NewSemaphore(false)
	cnt1 = 0
	for i := 0; i < acquirer; i++ {
		go acquire(s, i, t)
	}
	_sleep()
	s.notifyAll()
	go acquire(s, 100, t) // will be timeout
	_sleep()
	if cnt1 == acquirer && s.observer == 1 {
		t.Logf("observer=%d awake=%d chan.len=%d \n", s.observer, cnt1, cap(s.bus))
	} else {
		t.Errorf("observer=%d awake=%d chan.len=%d \n", s.observer, cnt1, cap(s.bus))
	}
}

func Test_sema_timeout(t *testing.T) {
	s := NewSemaphore(false)
	for i := 0; i < acquirer; i++ {
		go acquire(s, i, t)
	}
	time.Sleep(tmo)
	_sleep()

	if cnt2 == acquirer+1 && s.observer == 0 {
		t.Logf("observer=%d awake=%d chan.len=%d \n", s.observer, cnt2, cap(s.bus))
	} else {
		t.Errorf("observer=%d awake=%d chan.len=%d \n", s.observer, cnt2, cap(s.bus))
	}
}

func acquire(s *semaphore, id int, t *testing.T) {
	if s.acquire(tmo) {
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
	time.Sleep(time.Millisecond * 600)
}
