package tunnel

import (
	"crypto/sha1"
	"hash"
	"net"
	"sync"
	"time"
)

type Conn struct {
	net.Conn
	cipher     *Cipher
	rHash      hash.Hash
	wHash      hash.Hash
	identifier string
	wlock      sync.Locker
	priority   *TSPriority
}

func NewConnWithHash(conn *net.TCPConn) *Conn {
	return &Conn{
		Conn:  conn,
		rHash: sha1.New(),
		wHash: sha1.New(),
		wlock: new(sync.Mutex),
	}
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
	if c.rHash != nil && n > 0 {
		c.rHash.Write(b[:n])
	}
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
	if c.wHash != nil {
		c.wHash.Write(b)
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
		// SetKeepAlivePeriod(d time.Duration) error
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

func (c *Conn) FreeHash() {
	c.rHash = nil
	c.wHash = nil
}

func (c *Conn) RHashSum() []byte {
	hash := c.rHash.Sum(nil)
	c.rHash.Reset()
	c.rHash = nil
	return hash
}

func (c *Conn) WHashSum() []byte {
	hash := c.wHash.Sum(nil)
	c.wHash.Reset()
	c.wHash = nil
	return hash
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

func IdentifierOf(con net.Conn) string {
	if c, y := con.(*Conn); y && c.identifier != NULL {
		return c.identifier
	}
	return ipAddr(con.RemoteAddr())
}
