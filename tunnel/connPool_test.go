package tunnel

import (
	"container/list"
	"math/rand"
	"testing"
)

var (
	pool *ConnPool
	tmp  *list.List
)

func init() {
	pool = NewConnPool()
	tmp = list.New()
}

func Test_add_remove(t *testing.T) {
	n := randn(0xfff)
	for i := 0; i < n; i++ {
		c := NewConn(nil, nil)
		tmp.PushBack(c)
		pool.Push(c)
	}
	if l := pool.pool.Len(); l != n {
		t.Error("after push len=", l)
	}
	for e := tmp.Front(); e != nil; e = e.Next() {
		if !pool.Remove(e.Value.(*Conn)) {
			t.Error("remove failed")
		}
	}
	if l := pool.pool.Len(); l != 0 {
		t.Error("after remove len=", l)
	}
}

func Test_priority(t *testing.T) {
	n := randn(0xfff)
	for i := 0; i < n; i++ {
		pool.Push(NewConn(nil, nil))
	}
	for i := 0; i < n; i++ {
		p := &TSPriority{1, int64(i)}
		pool.pool[i].priority = p
	}
	c := pool.Select()
	if c.priority.rank != int64(n-2) {
		t.Errorf("select failed priority=%v", c.priority)
	}
}

func randn(m int) int {
	var n int
	for n < 4 {
		n = rand.Intn(m)
	}
	return n
}
