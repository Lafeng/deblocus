package tunnel

import (
	stdcrypto "crypto"

	"net"
	"net/url"
	"strconv"
	"strings"

	log "github.com/Lafeng/deblocus/glog"
	kcp "github.com/xtaci/kcp-go/v5"
)

type Transport struct {
	rawURL     string
	remoteAddr string
	provider   string
	cipher     string
	user       string
	pass       string
	pubKeyType string
	pubKey     stdcrypto.PublicKey
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

	switch u.Scheme {
	case "tcp":
		t.transType = "tcp"
		return nil
	case "kcp":
		t.transType = "kcp"
		goto kcp
	default:
		goto err
	}

kcp:
	{
		// kcp://kcpMode? mtu=1 & rwnd=2 & rbuf=3
		t.kcpMode = u.Host
		switch t.kcpMode {
		case "normal":
			t.kcpParams = []int{0, 40, 2, 1}
		case "fast":
			t.kcpParams = []int{0, 20, 2, 1}
		case "super":
			t.kcpParams = []int{0, 10, 2, 1}
		default:
			goto err
		}

		var params = values(u.Query())
		t.mtu, err = params.getInt("mtu", 1462)
		if err != nil {
			goto err
		}

		t.rwnd, err = params.getInt("rwnd", 1024)
		if err != nil {
			goto err
		}

		t.rbuf, err = params.getInt("rbuf", 1<<24)
		if err != nil {
			goto err
		}

		// all verified
		t.swnd = t.rwnd >> 1
		t.sbuf = t.rbuf >> 1
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
	if _, err = net.ResolveTCPAddr("tcp", url.Host); err != nil {
		return nil, HOST_UNREACHABLE.Apply(err)
	}

	var trans = Transport{
		rawURL:     uri,
		remoteAddr: url.Host,
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
		return t.remoteAddr
	}
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

func (t *Transport) dailTcpConnection() (net.Conn, error) {
	return net.DialTimeout("tcp", t.remoteAddr, GENERAL_SO_TIMEOUT)
}

func (t *Transport) dailKcpConnection() (net.Conn, error) {
	var kcpconn, err = kcp.DialWithOptions(t.remoteAddr, nil, KCP_FEC_DATASHARD, KCP_FEC_PARITYSHARD)
	if err != nil {
		return kcpconn, err
	}

	/*
		nodelay : Whether nodelay mode is enabled, 0 is not enabled; 1 enabled.
		interval ：Protocol internal work interval, in milliseconds, such as 10 ms or 20 ms.
		resend ：Fast retransmission mode, 0 represents off by default, 2 can be set (2 ACK spans will result in direct retransmission)
		nc ：Whether to turn off flow control, 0 represents “Do not turn off” by default, 1 represents “Turn off”.
		Normal Mode: ikcp_nodelay(kcp, 0, 40, 0, 0);
		Turbo Mode： ikcp_nodelay(kcp, 1, 10, 2, 1);
	*/
	// config.NoDelay, config.Interval, config.Resend, config.NoCongestion
	var p = t.kcpParams
	kcpconn.SetNoDelay(p[0], p[1], p[1], p[1])
	kcpconn.SetWindowSize(t.swnd, t.rwnd)
	kcpconn.SetMtu(t.mtu) // 1464
	kcpconn.SetACKNoDelay(true)
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)

	if err := kcpconn.SetDSCP(46); err != nil {
		log.Errorln("SetDSCP:", err)
	}
	if err := kcpconn.SetReadBuffer(t.rbuf); err != nil {
		log.Errorln("SetReadBuffer:", err)
	}
	if err := kcpconn.SetWriteBuffer(t.sbuf); err != nil {
		log.Errorln("SetWriteBuffer:", err)
	}
	return kcpconn, err
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

func CreateTCPServerListener(server *Server) (*net.TCPListener, error) {
	return net.ListenTCP("tcp", server.ListenAddr)
}

func CreateUDPServerListener(server *Server) (net.Listener, error) {
	return kcp.ListenWithOptions(server.Listen, nil, KCP_FEC_DATASHARD, KCP_FEC_PARITYSHARD)
}
