package tunnel

import (
	stdcrypto "crypto"
	"fmt"

	"net"
	"net/url"
	"strconv"
	"strings"

	log "github.com/Lafeng/deblocus/glog"
	kcp "github.com/xtaci/kcp-go/v5"
)

type Transport struct {
	rawURL     string
	remoteHost string
	provider   string
	cipher     string // todo: deprecated
	user       string
	pass       string
	host       string
	port       int
	pubKeyType string
	pubKey     stdcrypto.PublicKey
	asServer   bool
	transType  string
	kcpMode    string
	kcpParams  []int
	mtu        int
	swnd       int
	rwnd       int
	sbuf       int
	rbuf       int
}

func (t *Transport) parseTransport(str string) error {
	u, err := url.Parse(str)
	if err != nil {
		return err
	}

	// t.port for listen
	if t.port, err = strconv.Atoi(u.Port()); err != nil {
		return err
	}

	switch u.Scheme {
	case "tcp":
		t.transType = "tcp"
		return nil // TCP OK

	case "kcp":
		t.transType = "kcp"
		goto kcp

	default:
		goto err
	}

kcp:
	{
		// kcp://host:port /kcpMode? mtu=1 & rwnd=2 & rbuf=3
		// kcp://host:port /custom/1,2,3,4? mtu=1 & rwnd=2 & rbuf=3
		t.kcpMode = strings.TrimPrefix(u.Path, "/")
		switch t.kcpMode {
		case "normal":
			t.kcpParams = []int{0, 40, 7, 1}
		case "fast":
			t.kcpParams = []int{0, 20, 5, 1}
		case "turbo":
			t.kcpParams = []int{0, 10, 2, 1}
		default:
			if strings.HasPrefix(t.kcpMode, "custom/") {
				if t.kcpParams, err = toIntArray(t.kcpMode[7:], 4); err == nil {
					break
				}
			}
			goto err
		}

		var params = values(u.Query())
		if t.mtu, err = params.getInt("mtu", 1462); err != nil {
			goto err
		}

		if t.rwnd, err = params.getInt("rwnd", 1024); err != nil {
			goto err
		}

		if t.rbuf, err = params.getInt("rbuf", 1<<24); err != nil {
			goto err
		}

		// all verified
		if t.asServer {
			t.swnd = t.rwnd
			t.sbuf = t.rbuf
		} else {
			t.swnd = t.rwnd >> 1
			t.sbuf = t.rbuf >> 1
		}
		return nil
	}

err:
	return CONF_ERROR.Apply(str)
}

func newTransport(uri string) (*Transport, error) {
	// url scheme
	url, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if url.Scheme != "d5" {
		return nil, CONF_ERROR.Apply(url.Scheme)
	}

	// host
	var remoteHost = url.Hostname()
	if IsValidHost(remoteHost) != nil {
		return nil, HOST_UNREACHABLE.Apply(url.Host)
	}

	var trans = Transport{
		rawURL:     uri,
		remoteHost: remoteHost,
		transType:  "tcp",
	}

	// user, passwd
	userInfo := url.User
	if userInfo == nil || userInfo.Username() == NULL {
		return nil, CONF_MISS.Apply("user")
	}
	passwd, ok := userInfo.Password()
	if !ok || passwd == NULL {
		return nil, CONF_MISS.Apply("passwd")
	}
	trans.user = userInfo.Username()
	trans.pass = passwd

	// path
	var path = strings.Trim(url.Path, "/")
	// compatible with 0.13x version
	path = strings.ReplaceAll(path, "=", "/")
	var pathParts = strings.Split(path, "/")

	if len(pathParts) != 3 {
		return nil, CONF_ERROR.Apply(url.Path)
	}

	// provider, pubkey, cipher
	trans.provider = pathParts[0]
	trans.pubKeyType = pathParts[1]
	trans.cipher = pathParts[2]
	// verify cipher
	_, err = GetAvailableCipher(trans.cipher)
	if err != nil {
		return nil, err
	}

	return &trans, nil
}

func (t *Transport) RemoteName() string {
	if t.provider != NULL {
		return t.provider
	} else {
		return t.remoteHost
	}
}

func (t *Transport) TransType() string {
	return t.transType
}

func (t *Transport) toURL() string {
	switch t.transType {
	case "tcp":
		return fmt.Sprintf("tcp://:%d", t.port)
	case "kcp":
		return fmt.Sprintf("kcp://:%d/%s", t.port, "fast")
	}
	return ""
}

func (t *Transport) Dail() (net.Conn, error) {
	switch t.transType {
	case "tcp":
		return t.dailTcpConnection()
	case "kcp":
		return t.dailKcpConnection()
	}
	return nil, ILLEGAL_STATE
}

func (t *Transport) remoteAddr() string {
	return fmt.Sprint(t.remoteHost, ":", t.port)
}

func (t *Transport) dailTcpConnection() (net.Conn, error) {
	return net.DialTimeout("tcp", t.remoteAddr(), GENERAL_SO_TIMEOUT)
}

func (t *Transport) dailKcpConnection() (net.Conn, error) {
	var kcpconn, err = kcp.DialWithOptions(t.remoteAddr(), nil, KCP_FEC_DATASHARD, KCP_FEC_PARITYSHARD)
	if err != nil {
		return kcpconn, err
	}
	err = t.setupKcpConnection(kcpconn)
	return kcpconn, err
}

const DSCP_EF = 46

func (t *Transport) setupKcpConnection(kcpconn *kcp.UDPSession) (err error) {
	// nodelay : Whether nodelay mode is enabled, 0 is not enabled; 1 enabled.
	// interval ：Protocol internal work interval, in milliseconds, such as 10 ms or 20 ms.
	// resend ：Fast retransmission mode, 0 represents off by default, 2 can be set (2 ACK spans will result in direct retransmission)
	// nc ：Whether to turn off flow control, 0 represents “Do not turn off” by default, 1 represents “Turn off”.
	// Normal Mode: ikcp_nodelay(kcp, 0, 40, 0, 0);
	// Turbo Mode： ikcp_nodelay(kcp, 1, 10, 2, 1);
	var p = t.kcpParams
	// config.NoDelay, config.Interval, config.Resend, config.NoCongestion
	kcpconn.SetNoDelay(p[0], p[1], p[2], p[3])
	kcpconn.SetWindowSize(t.swnd, t.rwnd)
	kcpconn.SetMtu(t.mtu) // 1464
	kcpconn.SetACKNoDelay(true)
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)

	if !t.asServer {
		if err = kcpconn.SetDSCP(DSCP_EF); err != nil {
			log.Errorln("SetDSCP:", err)
			goto returnErr
		}
		if err = kcpconn.SetReadBuffer(t.rbuf); err != nil {
			log.Errorln("SetReadBuffer:", err)
			goto returnErr
		}
		if err = kcpconn.SetWriteBuffer(t.sbuf); err != nil {
			log.Errorln("SetWriteBuffer:", err)
			goto returnErr
		}
	}
	return nil

returnErr:
	return err
}

func (t *Transport) setupKcpListener(listener *kcp.Listener) (err error) {
	if err = listener.SetDSCP(DSCP_EF); err != nil {
		log.Errorln("SetDSCP:", err)
		goto returnErr
	}
	if err = listener.SetReadBuffer(t.rbuf); err != nil {
		log.Errorln("SetReadBuffer:", err)
		goto returnErr
	}
	if err = listener.SetWriteBuffer(t.sbuf); err != nil {
		log.Errorln("SetWriteBuffer:", err)
		goto returnErr
	}
	return nil

returnErr:
	return err
}

func (t *Transport) SetupConnection(conn net.Conn) {
	if kcpconn, ok := conn.(*kcp.UDPSession); ok {
		t.setupKcpConnection(kcpconn)
	}
}

func (t *Transport) CreateServerListener(server *Server) (net.Listener, error) {
	switch t.transType {
	case "tcp":
		addr := net.TCPAddr{Port: t.port}
		return net.ListenTCP("tcp", &addr)
	case "kcp":
		addr := fmt.Sprintf(":%d", t.port)
		if ln, err := kcp.ListenWithOptions(addr, nil, KCP_FEC_DATASHARD, KCP_FEC_PARITYSHARD); err == nil {
			err = t.setupKcpListener(ln)
			return ln, err
		} else {
			return nil, err
		}
	}
	return nil, ILLEGAL_STATE
}

type values url.Values

func (v values) getOne(k string) string {
	var arr = v[k]
	if len(arr) == 0 {
		return ""
	} else {
		return arr[0]
	}
}

func (v values) getInt(k string, defaultValue int) (int, error) {
	var value = v.getOne(k)
	if value == NULL {
		return defaultValue, nil
	} else {
		return strconv.Atoi(value)
	}
}
