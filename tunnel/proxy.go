package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	PROT_SOCKS4  = 0
	PROT_UNKNOWN = 1
	PROT_SOCKS5  = 2
	PROT_HTTP    = 3
	PROT_HTTP_T  = 4
	PROT_LOCAL   = 5
)

const (
	HTTP_PROXY_STATUS_LINE = "HTTP/1.1 200 Connection established"
	CRLF                   = "\r\n"
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
		exception.Spawn(&err, "socks: read header [% x]", buf)
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

	var proto int
	switch {
	case head == 5:
		proto = PROT_SOCKS5
	case head >= 'A' && head <= 'z':
		proto = PROT_HTTP
	case head == 4: // socks4, socks4a
		proto = PROT_SOCKS4
	default:
		proto = PROT_UNKNOWN
	}

	if DEBUG && proto == PROT_UNKNOWN {
		var t = make([]byte, 100)
		copy(t, b)
		pbconn.Read(t[2:])
		dumpHex("proto head", t)
	}
	return proto, nil
}

func httpProxyHandshake(conn *pushbackInputStream) (proto int, target string, err error) {
	var req *http.Request
	reader := bufio.NewReader(conn)
	setRTimeout(conn)
	req, err = http.ReadRequest(reader)
	if err != nil {
		return
	}

	// http tunnel, direct into tunnel
	if req.Method == "CONNECT" {
		proto = PROT_HTTP_T
		target = req.Host

		// response http header
		setWTimeout(conn)
		_, err = fmt.Fprint(conn, HTTP_PROXY_STATUS_LINE, CRLF, CRLF)
		if err != nil {
			return
		}

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
			buf := new(bytes.Buffer)
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
	initTplOnce.Do(lazyInitTemplate)
	defer conn.Close()

	switch reqUri {
	case "/wpad.dat":
		if c.pacFile != NULL { // has pac setting
			pacFile, info, err := openReadOnlyFile(c.pacFile)
			if err != nil {
				log.Errorln("Read PAC file", err)
				goto error404
			}
			defer pacFile.Close()
			entity := respEntity{
				contentType:   "application/x-ns-proxy-autoconfig",
				contentLength: int(info.Size()),
				stream:        pacFile,
			}
			writeHttpResponse(conn, 200, &entity)
			return
		}
	case "/":
		writeHttpResponse(conn, 200, c.renderPage("main"))
		return
	}

error404:
	// other local request or pacFile not specified
	log.Warningln("Unrecognized Request", reqUri)
	// respond 404
	writeHttpResponse(conn, 404, c.renderPage("404"))
}

func writeHttpResponse(conn net.Conn, statusCode int, content interface{}) {
	var entity respEntity
	var isStream bool
	var text []byte
	switch body := content.(type) {
	case *respEntity:
		entity, isStream = *body, true
	case []byte:
		entity.contentLength, text = len(body), body
	case string:
		entity.contentLength, text = len(body), []byte(body)
	}
	if len(text) > 0 {
		if text[0] == '<' {
			entity.contentType = "text/html"
		} else {
			entity.contentType = "text/plain"
		}
	}
	buf := new(bytes.Buffer)
	fmt.Fprint(buf, "HTTP/1.1 ", statusCode, " ", http.StatusText(statusCode), CRLF)
	fmt.Fprint(buf, "Content-Type: ", entity.contentType, CRLF)
	fmt.Fprint(buf, "Content-Length: ", entity.contentLength, CRLF, CRLF)
	setWTimeout(conn)
	_, err := conn.Write(buf.Bytes())
	if err == nil {
		if isStream {
			io.Copy(conn, entity.stream)
		} else {
			conn.Write(text)
		}
	}
}

var (
	webPanelTpl     *template.Template
	webPanelBuilder = make(map[string]pageDataBuilder)
	initTplOnce     = new(sync.Once)
	startTime       = time.Now()
)

type respEntity struct {
	contentType   string
	contentLength int
	stream        io.Reader
}

type pageDataBuilder func(*Client) interface{}

func lazyInitTemplate() {
	webPanelTpl = template.New("")
	var tpl *template.Template
	// main
	tpl = template.Must(template.New("main").Parse(_TPL_PAGE_MAIN))
	webPanelTpl.AddParseTree(tpl.Name(), tpl.Tree)
	webPanelBuilder[tpl.Name()] = buildMainPageData
	// 404
	tpl = template.Must(template.New("404").Parse(_TPL_PAGE_404))
	webPanelTpl.AddParseTree(tpl.Name(), tpl.Tree)
	webPanelBuilder[tpl.Name()] = build404PageData
}

func (c *Client) renderPage(page string) []byte {
	builder := webPanelBuilder[page]
	data := builder(c)
	buf := new(bytes.Buffer)
	webPanelTpl.ExecuteTemplate(buf, page, data)
	return buf.Bytes()
}

type mainPageData struct {
	Version    string
	StartTime  time.Time
	ReqCount   int32
	Round      int32
	AvgRtt     int32
	Ready      bool
	Connection string
}

func buildMainPageData(c *Client) interface{} {
	var rtt int32
	if c.mux != nil {
		rtt = atomic.LoadInt32(&c.mux.sRtt)
	}
	data := mainPageData{
		Version:    VER_STRING,
		StartTime:  startTime,
		ReqCount:   atomic.LoadInt32(&c.reqCnt),
		Round:      atomic.LoadInt32(&c.round),
		Ready:      c.IsReady(),
		AvgRtt:     rtt,
		Connection: c.transport.rawURL,
	}
	if data.Round > 0 {
		data.Round--
	}
	return &data
}

func build404PageData(c *Client) interface{} {
	return &mainPageData{
		Version: VER_STRING,
	}
}
