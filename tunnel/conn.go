package tunnel

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"net"
	"sync"
	//"syscall"
	"time"
	//"unsafe"
)

type Conn struct {
	net.Conn
	cipher     *Cipher
	identifier string
	wlock      sync.Locker
	priority   *TSPriority
}

func NewConn(conn *net.TCPConn, cipher *Cipher) *Conn {
	return &Conn{
		Conn:   conn,
		cipher: cipher,
		wlock:  new(sync.Mutex),
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.cipher != nil {
		c.cipher.decrypt(b[:n], b[:n])
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	c.wlock.Lock()
	defer c.wlock.Unlock()
	if c.cipher != nil {
		c.cipher.encrypt(b, b)
	}
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

func (c *Conn) SetSockOpt(disableDeadline, keepAlive, noDelay int8) {
	if disableDeadline > 0 {
		c.Conn.SetDeadline(ZERO_TIME)
	}
	if t, y := c.Conn.(*net.TCPConn); y {
		if keepAlive >= 0 {
			t.SetKeepAlive(keepAlive > 0)
			if keepAlive > 0 {
				t.SetKeepAlivePeriod(time.Second * 90)
			}
		}
		if noDelay >= 0 {
			t.SetNoDelay(noDelay > 0)
		}
	}
}

func (c *Conn) Update() {
	n := time.Now().UnixNano()
	if d := n - c.priority.last; d < 1e9 {
		if d <= 0 {
			c.priority.rank -= 1e9
		} else {
			c.priority.rank -= 1e9 / d
		}
	} else {
		c.priority.rank = 1e9
	}
	c.priority.last = n
}

func (c *Conn) sign() string {
	return fmt.Sprintf("L%dR%d", c.LocalAddr().(*net.TCPAddr).Port, c.RemoteAddr().(*net.TCPAddr).Port)
}

func IdentifierOf(con net.Conn) string {
	return con.LocalAddr().String() + con.RemoteAddr().String()
}

/*
func netFd_of_TCPConn(c net.Conn) syscall.Handle {
	if t, y := c.(*net.TCPConn); y {
		var p = *(*uintptr)(unsafe.Pointer(t)) // value of tcpconn.field0 == pointer == *netFd
		p += uintptr(16)                       // sizeof fdMutex struct: /src/net/fd_mutex.go
		fd := *(*syscall.Handle)(unsafe.Pointer(p))
		n, err := syscall.Getsockname(fd)
		fmt.Println(n, err)
		return fd
	}
	return syscall.InvalidHandle
}
*/

type hashedConn struct {
	*Conn
	rHash hash.Hash
	wHash hash.Hash
}

func NewConnWithHash(conn *net.TCPConn) *hashedConn {
	return &hashedConn{
		Conn:  &Conn{Conn: conn, wlock: new(sync.Mutex)},
		rHash: sha1.New(),
		wHash: sha1.New(),
	}
}

func (c *hashedConn) Read(b []byte) (n int, e error) {
	n, e = c.Conn.Read(b)
	if c.rHash != nil && n > 0 {
		c.rHash.Write(b[:n])
	}
	return
}

func (c *hashedConn) Write(b []byte) (int, error) {
	if c.wHash != nil {
		c.wHash.Write(b)
	}
	return c.Conn.Write(b)
}

func (c *hashedConn) FreeHash() {
	c.rHash = nil
	c.wHash = nil
}

func (c *hashedConn) RHashSum() []byte {
	hash := c.rHash.Sum(nil)
	c.rHash.Reset()
	c.rHash = nil
	return hash
}

func (c *hashedConn) WHashSum() []byte {
	hash := c.wHash.Sum(nil)
	c.wHash.Reset()
	c.wHash = nil
	return hash
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
