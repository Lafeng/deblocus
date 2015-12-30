package tunnel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Conn struct {
	net.Conn
	cipher     cipherKit
	identifier string
	wlock      sync.Locker
	priority   *TSPriority
}

func NewConn(conn net.Conn, cipher cipherKit) *Conn {
	return &Conn{
		Conn:   conn,
		cipher: cipher,
		wlock:  new(sync.Mutex),
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.cipher.decrypt(b[:n], b[:n])
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	c.wlock.Lock()
	defer c.wlock.Unlock()
	c.cipher.encrypt(b, b)
	return c.Conn.Write(b)
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func (c *Conn) CloseRead() {
	if conn, ok := c.Conn.(*net.TCPConn); ok {
		conn.CloseRead()
	}
}

func (c *Conn) CloseWrite() {
	if conn, ok := c.Conn.(*net.TCPConn); ok {
		conn.CloseWrite()
	}
}

// bool: disableDeadline
// int8: minutes of KeepAlivePeriod, zero to disable
// bool: noDelay
func (c *Conn) SetSockOpt(disableDeadline, keepAlive, noDelay int8) {
	if disableDeadline > 0 {
		c.Conn.SetDeadline(ZERO_TIME)
	}
	if t, y := c.Conn.(*net.TCPConn); y {
		if keepAlive >= 0 {
			t.SetKeepAlive(keepAlive > 0)
			if keepAlive > 0 {
				period := int64(time.Minute) * int64(keepAlive)
				period += randomHalving(period)
				t.SetKeepAlivePeriod(time.Duration(period))
			}
		}
		if noDelay >= 0 {
			t.SetNoDelay(noDelay > 0)
		}
	}
}

func (c *Conn) Update() {
	var rk, t int64 = 0, time.Now().UnixNano()
	if d := t - c.priority.last; d < 1e9 {
		if d <= 0 {
			rk = 1e9
		} else {
			rk = 1e9 / d
		}
	}
	if rk > 0 {
		atomic.AddInt64(&c.priority.rank, -rk)
	} else {
		atomic.StoreInt64(&c.priority.rank, 1e9)
	}
	c.priority.last = t
}

func (c *Conn) id() string {
	return fmt.Sprintf("L%dR%d", c.LocalAddr().(*net.TCPAddr).Port, c.RemoteAddr().(*net.TCPAddr).Port)
}

//
// PushbackInputStream
//
type pushbackInputStream struct {
	net.Conn
	buffer []byte
}

func NewPushbackInputStream(conn net.Conn) *pushbackInputStream {
	return &pushbackInputStream{Conn: conn}
}

func (s *pushbackInputStream) Read(b []byte) (int, error) {
	if bl := len(s.buffer); bl > 0 {
		n := copy(b, s.buffer)
		if n >= bl {
			s.buffer = nil
		} else {
			s.buffer = s.buffer[n:]
		}
		return n, nil
	} else {
		return s.Conn.Read(b)
	}
}

func (s *pushbackInputStream) WriteString(str string) (int, error) {
	return s.Write([]byte(str))
}

func (s *pushbackInputStream) Unread(b []byte) {
	s.buffer = append(s.buffer, b...)
}

func (s *pushbackInputStream) HasRemains() bool {
	return len(s.buffer) > 0
}
