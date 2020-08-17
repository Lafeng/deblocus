package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func SafeClose(conn net.Conn) {
	defer func() {
		_ = recover()
	}()
	if conn != nil {
		conn.Close()
	}
}

func closeR(conn net.Conn) {
	defer func() { _ = recover() }()
	if t, y := conn.(*net.TCPConn); y {
		t.CloseRead()
	} else {
		conn.Close()
	}
}

func closeW(conn net.Conn) {
	defer func() { _ = recover() }()
	if t, y := conn.(*net.TCPConn); y {
		t.CloseWrite()
	} else {
		conn.Close()
	}
}

func IsValidHost(addr string) (err error) {
	var h string
	h, _, err = net.SplitHostPort(addr + ":1")
	if err != nil {
		return
	}
	if h == NULL {
		err = errors.New("Invalid address " + addr)
	}
	return
}

func IsClosedError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "closed") || strings.Contains(msg, "reset")
}

func setRTimeout(conn net.Conn) {
	e := conn.SetReadDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
	ThrowErr(e)
}

func setWTimeout(conn net.Conn) {
	e := conn.SetWriteDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
	ThrowErr(e)
}

func IsTimeout(err error) bool {
	var netError, ok = err.(net.Error)
	if ok { // tcp timeout
		return netError.Timeout()
	} else {
		// kcp: sess.go L47
		// errTimeout          = errors.New("timeout")
		return err.Error() == "timeout"
	}
}

func port(addr net.Addr) int {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.Port
	case *net.UDPAddr:
		return v.Port
	default:
		return 0
	}
}

// isIPv4 returns true if the Addr contains an IPv4 address.
func isIPv4(addr net.Addr) bool {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return addr.IP.To4() != nil
	case *net.UDPAddr:
		return addr.IP.To4() != nil
	case *net.IPAddr:
		return addr.IP.To4() != nil
	case *net.IPNet:
		return addr.IP.To4() != nil
	}
	return false
}

func ipAddr(addr net.Addr) string {
	switch addr.(type) {
	case *net.TCPAddr:
		return addr.(*net.TCPAddr).IP.String()
	case *net.UDPAddr:
		return addr.(*net.UDPAddr).IP.String()
	case *net.IPAddr:
		return addr.(*net.IPAddr).IP.String()
	}
	return addr.String()
}

func determineDualStack() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	var v4, v6 uint32
	for _, iface := range ifaces {
		if iface.Flags|net.FlagUp != 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if isGlobal(addr) {
					if isIPv4(addr) {
						v4++
					} else {
						v6++
					}
				}
			}
		}
	}
	return v4*v6 != 0
}

func isGlobalAddr(addr string) bool {
	if a, _ := net.ResolveIPAddr("ip", addr); a != nil {
		return isGlobal(a)
	}
	return false
}

func isGlobal(addr net.Addr) bool {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.IsGlobalUnicast()
	case *net.UDPAddr:
		return a.IP.IsGlobalUnicast()
	case *net.IPAddr:
		return a.IP.IsGlobalUnicast()
	case *net.IPNet:
		return a.IP.IsGlobalUnicast()
	}
	return false
}

func findServerListenPort(addr string) int {
	n, e := net.ResolveTCPAddr("tcp", addr)
	if e != nil {
		return 9008
	}
	return n.Port
}

func findFirstUnicastAddress() string {
	nic, e := net.InterfaceAddrs()
	if nic != nil && e == nil {
		for _, v := range nic {
			if i, _ := v.(*net.IPNet); i != nil {
				if i.IP.IsGlobalUnicast() {
					var ipStr = i.IP.String()
					if len(i.IP) == net.IPv6len {
						return fmt.Sprint("[", ipStr, "]")
					} else {
						return ipStr
					}
				}
			}
		}
	}
	return NULL
}
