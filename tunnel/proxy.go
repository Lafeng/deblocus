package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Lafeng/deblocus/exception"
	log "github.com/Lafeng/deblocus/glog"
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
	PROT_LOCAL   = 5
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

		// sure this is local static request
		// req.RequestURI.length >= 1
		if req.Method == "GET" && req.RequestURI[0] == '/' {
			proto = PROT_LOCAL
			target = req.RequestURI
			return

		} else { // plain http proxy request
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

func openReadOnlyFile(file string) (f *os.File, info os.FileInfo, err error) {
	f, err = os.Open(file)
	if err == nil {
		info, err = f.Stat()
	}
	return
}

func (c *Client) localServlet(conn net.Conn, reqUri string) {
	defer conn.Close()

	switch reqUri {
	case "/wpad.dat":
		if c.connInfo.pacFile != NULL { // has pac setting
			pacFile, info, err := openReadOnlyFile(c.connInfo.pacFile)
			if err != nil {
				log.Errorln("read PAC file", err)
				goto error404
			}
			defer pacFile.Close()
			buf := new(bytes.Buffer)
			fmt.Fprint(buf, "HTTP/1.1 200 OK", CRLF)
			fmt.Fprint(buf, "Content-Type: application/x-ns-proxy-autoconfig", CRLF)
			fmt.Fprint(buf, "Content-Length: ", info.Size(), CRLF, CRLF)
			setWTimeout(conn)
			if _, err = conn.Write(buf.Bytes()); err == nil {
				io.Copy(conn, pacFile)
			}
			return
		}
	case "/":
		content := c.renderMainPage()
		fmt.Fprint(conn, "HTTP/1.1 200 OK", CRLF)
		fmt.Fprint(conn, "Content-Type: text/html", CRLF)
		fmt.Fprint(conn, "Content-Length: ", len(content), CRLF, CRLF)
		conn.Write(content)
		return
	}

error404:
	// other local request or pacFile not specified
	log.Warningln("Unrecognized Request", reqUri)
	// respond 404
	setWTimeout(conn)
	fmt.Fprint(conn, "HTTP/1.1 404 Not found", CRLF, CRLF)
}

var (
	mainPageTpl *template.Template
	initTplOnce = new(sync.Once)
	startTime   = time.Now()
)

type mainPageData struct {
	Version   string
	StartTime time.Time
	NReq      uint32
}

func lazyInitTemplate() {
	mainPageTpl = template.Must(template.New("main").Parse(_TPL_WEBPANEL))
}

func (c *Client) renderMainPage() []byte {
	initTplOnce.Do(lazyInitTemplate)
	data := mainPageData{
		Version:   VER_STRING,
		StartTime: startTime,
		NReq:      sid_seq,
	}
	buf := new(bytes.Buffer)
	mainPageTpl.Execute(buf, &data)
	return buf.Bytes()
}
