package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/golang/glog"
)

const (
	IPV4   byte = 1
	DOMAIN byte = 3
	IPV6   byte = 4
	S4_VER byte = 4
	S5_VER byte = 5
)

const (
	PROT_UNKNOWN = 1
	PROT_SOCKS5  = 2
	PROT_HTTP    = 3
	PROT_HTTP_T  = 4
)

const (
	HTTP_PROXY_VER_LINE = "HTTP/1.1 200 Connection established"
	HTTP_PROXY_AGENT    = "Proxy-Agent: "
	CRLF                = "\r\n"
)

var (
	// socks5 exceptions
	INVALID_SOCKS5_HEADER = exception.New("Invalid socks5 header")
	HOST_UNREACHABLE      = exception.New("Host is unreachable")
)

// socks5 protocol handler in client side
// Ref: https://www.ietf.org/rfc/rfc1928.txt
type socks5Handler struct {
	conn net.Conn
}

// step1-2
func (s socks5Handler) handshake() bool {
	var buf = make([]byte, 2)
	var n, nmethods int
	var ver byte
	setRTimeout(s.conn)
	_, err := io.ReadFull(s.conn, buf)
	if err != nil {
		exception.Spawn(&err, "socks: read header")
		goto errLogging
	}

	ver, nmethods = buf[0], int(buf[1])
	if ver != S5_VER || nmethods < 1 {
		err = INVALID_SOCKS5_HEADER
		exception.Spawn(&err, "socks: read header [% x]", buf[:2])
		goto errHandler
	}

	buf = make([]byte, nmethods+1) // consider method non-00
	setRTimeout(s.conn)
	n, err = io.ReadAtLeast(s.conn, buf, nmethods)
	if err != nil || n != nmethods {
		err = INVALID_SOCKS5_HEADER
		exception.Spawn(&err, "socks: read header [% x]", hex.EncodeToString(buf))
		goto errHandler
	}

	// accept
	buf = []byte{5, 0}
	setWTimeout(s.conn)
	_, err = s.conn.Write(buf)
	if err == nil {
		return true
	} else {
		err = exception.Spawn(&err, "socks: write response")
		goto errLogging
	}

errHandler:
	// handshake error feedback
	// NO ACCEPTABLE METHODS
	buf = []byte{5, 0xff}
	setWTimeout(s.conn)
	s.conn.Write(buf)
errLogging:
	log.Warningln(err)
	return false
}

// step3-4
func (s socks5Handler) readRequest() (string, bool) {
	var (
		buf            = make([]byte, 262) // 4+(1+255)+2
		host           string
		ofs            int
		ver, cmd, atyp byte
	)
	var msg = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	setRTimeout(s.conn)
	_, err := s.conn.Read(buf)
	if err != nil {
		exception.Spawn(&err, "socks: read request")
		goto errLogging
	}
	ver, cmd, atyp = buf[0], buf[1], buf[3]
	if ver != S5_VER || cmd != 1 {
		exception.Spawn(&err, "socks: invalid request")
		goto errHandler
	}

	buf = buf[4:]
	switch atyp {
	case IPV4:
		host = net.IP(buf[:net.IPv4len]).String()
		ofs = net.IPv4len
	case IPV6:
		host = "[" + net.IP(buf[:net.IPv6len]).String() + "]"
		ofs = net.IPv6len
	case DOMAIN:
		dlen := int(buf[0])
		ofs = dlen + 1
		host = string(buf[1:ofs])
		// literal IPv6
		if strings.Count(host, ":") >= 2 && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
	default:
		exception.Spawn(&err, "socks: invalid request")
		goto errHandler
	}

	// accept
	_, err = s.conn.Write(msg)
	if err != nil {
		exception.Spawn(&err, "socks: write response")
		goto errLogging
	}

	host += ":" + strconv.Itoa(int(binary.BigEndian.Uint16(buf[ofs:])))
	return host, true

errHandler:
	msg[1] = 0x1 // general SOCKS server failure
	setWTimeout(s.conn)
	s.conn.Write(msg)
errLogging:
	log.Warningln(err)

	return NULL, false
}

// determines protocol of client req
func detectProtocol(pbconn *pushbackInputStream) (int, error) {
	var b = make([]byte, 2)
	setRTimeout(pbconn)
	n, e := io.ReadFull(pbconn, b)
	if n != 2 {
		return 0, io.ErrUnexpectedEOF
	}
	if e != nil {
		return 0, e
	}

	defer pbconn.Unread(b)
	var head = b[0]

	switch {
	case head == 5:
		return PROT_SOCKS5, nil
	case head >= 'A' && head <= 'z':
		return PROT_HTTP, nil
	case head == 4: // socks4, socks4a
		return PROT_UNKNOWN, nil
	default:
		return PROT_UNKNOWN, nil
	}
}

func httpProxyHandshake(conn *pushbackInputStream) (proto int, target string, err error) {
	var req *http.Request
	reader := bufio.NewReader(conn)
	setRTimeout(conn)
	req, err = http.ReadRequest(reader)
	if err != nil {
		return
	}

	buf := new(bytes.Buffer)
	// http tunnel, direct into tunnel
	if req.Method == "CONNECT" {
		proto = PROT_HTTP_T
		target = req.Host

		// response http header
		buf.WriteString(HTTP_PROXY_VER_LINE)
		buf.WriteString(CRLF)
		buf.WriteString(HTTP_PROXY_AGENT + "/" + VER_STRING)
		buf.WriteString(CRLF + CRLF)
		setWTimeout(conn)
		conn.Write(buf.Bytes())

	} else { // plain http request
		proto = PROT_HTTP
		target = req.Host

		// delete http header Proxy-xxx
		for k, _ := range req.Header {
			if strings.HasPrefix(k, "Proxy") {
				delete(req.Header, k)
			}
		}
		// serialize modified request to buffer
		req.Write(buf)
		// rollback
		conn.Unread(buf.Bytes())
	}

	if target == NULL {
		err = errors.New("missing host in address")
		return
	}

	_, _, err = net.SplitHostPort(target)
	if err != nil {
		// plain http request: the header.Host without port
		if strings.Contains(err.Error(), "missing port") {
			err = nil
			if req.Method == "CONNECT" {
				target += ":443"
			} else {
				target += ":80"
			}
		} else {
			return
		}
	}
	return
}
