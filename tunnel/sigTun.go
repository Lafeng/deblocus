package tunnel

import (
	"encoding/binary"
	ex "github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	"sync"
	"time"
)

const (
	CMD_HEADER_LEN    = 16
	CTL_PING          = byte(1)
	CTL_PONG          = byte(2)
	TOKEN_REQUEST     = byte(5)
	TOKEN_REPLY       = byte(6)
	CTL_PING_INTERVAL = uint16(180) // time.Second
)

type signalTunnel struct {
	tun           *Conn
	remoteAddr    string
	lived         *time.Timer
	lock          sync.Locker
	interval      time.Duration
	baseInterval  time.Duration
	lastResetTime int64
}

func NewSignalTunnel(conn *Conn, interval int) *signalTunnel {
	var bi, i time.Duration
	if interval >= 30 && interval <= 300 {
		bi = time.Duration(interval) * time.Second
		i = 2 * bi
	} else {
		i = time.Duration(CTL_PING_INTERVAL) * time.Second
		bi = i
	}
	t := &signalTunnel{
		tun:          conn,
		remoteAddr:   IdentifierOf(conn),
		lock:         new(sync.Mutex),
		interval:     i,
		baseInterval: bi,
	}
	t.lived = time.AfterFunc(i, t.areYouAlive)
	return t
}

func (t *signalTunnel) start(handler event_handler) {
	defer func() {
		ex.CatchException(recover())
		if t.lived != nil {
			// must clear timer
			t.lived.Stop()
		}
		if handler != nil {
			handler(evt_st_closed, true)
		}
	}()
	buf := make([]byte, CMD_HEADER_LEN)
	for {
		n, err := t.tun.Read(buf)
		if err != nil {
			log.Warningln("Exiting signalTunnel caused by", err)
			break
		}
		if n == CMD_HEADER_LEN {
			cmd := buf[0]
			argslen := binary.BigEndian.Uint16(buf[2:])
			if argslen > 0 {
				argsbuf := make([]byte, argslen)
				n, err = t.tun.Read(argsbuf)
				handler(evt_st_msg, cmd, argsbuf)
			} else {
				switch cmd {
				case CTL_PING: // reply
					go t.imAlive()
				case CTL_PONG: // aware of living
					go t.acknowledged()
				default:
					handler(evt_st_msg, cmd)
				}
			}
		} else {
			log.Errorln("Abnormal command", buf, err)
			continue
		}
	}
}

func (t *signalTunnel) postCommand(cmd byte, args []byte) (n int, err error) {
	t.lock.Lock()
	defer func() {
		t.lock.Unlock()
		t.tun.SetWriteDeadline(ZERO_TIME)
	}()
	buf := randArray(CMD_HEADER_LEN, CMD_HEADER_LEN)
	buf[0] = cmd
	binary.BigEndian.PutUint16(buf[2:], uint16(len(args)))
	if args != nil {
		buf = append(buf, args...)
	}
	if log.V(5) {
		log.Infof("send command packet=[% x]\n", buf)
	}
	t.tun.SetWriteDeadline(time.Now().Add(GENERAL_SO_TIMEOUT * 2))
	n, err = t.tun.Write(buf)
	return
}

func (t *signalTunnel) active(times int64) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if times > 0 { // active link in transferring
		var d = (times - t.lastResetTime) << 1
		// allow reset at least half interval
		if d > int64(t.interval/time.Second) {
			if log.V(5) {
				log.Infoln("suppress the next ping task")
			}
			t.lastResetTime = times
			t.lived.Reset(t.interval)
		}
	} else if times < 0 { // scheduled ping
		t.interval = t.baseInterval * time.Duration(-times)
		t.lastResetTime = time.Now().Unix()
		t.lived.Reset(t.interval)
	}
}

func (t *signalTunnel) areYouAlive() {
	if log.V(5) {
		log.Infoln("Ping/launched to", t.remoteAddr)
	}
	_, err := t.postCommand(CTL_PING, nil)
	// Either waiting pong timeout or send ping failed
	if err != nil {
		SafeClose(t.tun)
		log.Warningln("Ping remote failed and then closed", t.remoteAddr, err)
	} else {
		t.tun.SetReadDeadline(time.Now().Add(GENERAL_SO_TIMEOUT * 2))
		// impossible call by timer, will reset by acknowledged or read timeout.
		t.active(-1)
	}
}

func (t *signalTunnel) acknowledged() {
	if log.V(5) {
		log.Infoln("Ping/acknowledged by", t.remoteAddr)
	}
	t.tun.SetReadDeadline(ZERO_TIME)
	t.active(-2) // so slow down the tempo
}

func (t *signalTunnel) imAlive() {
	if log.V(5) {
		log.Infoln("Ping/responded to", t.remoteAddr)
	}
	t.active(-1) // up tempo for become a sender
	_, err := t.postCommand(CTL_PONG, nil)
	if err != nil {
		SafeClose(t.tun)
		log.Warningln("Reply ping failed and then closed", t.remoteAddr, err)
	}
}
