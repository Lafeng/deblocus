package tunnel

import (
	"net"
	"time"
)

func resolveAddrList(op, net, addr string, deadline time.Time) (addrList, error)
func dialSerial(ctx *dialContext, ras addrList, cancel <-chan struct{}) (net.Conn, error)

// A Dialer contains options for connecting to an address.
//
// The zero value for each field is equivalent to dialing
// without that option. Dialing with the zero value of Dialer
// is therefore equivalent to just calling the Dial function.
type Dialer struct {
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. If Deadline is also set, it may fail
	// earlier.
	//
	// The default is no timeout.
	//
	// When dialing a name with multiple IP addresses, the timeout
	// may be divided between them.
	//
	// With or without a timeout, the operating system may impose
	// its own earlier timeout. For instance, TCP timeouts are
	// often around 3 minutes.
	Timeout time.Duration

	// Deadline is the absolute point in time after which dials
	// will fail. If Timeout is set, it may fail earlier.
	// Zero means no deadline, or dependent on the operating system
	// as with the Timeout option.
	Deadline time.Time

	// LocalAddr is the local address to use when dialing an
	// address. The address must be of a compatible type for the
	// network being dialed.
	// If nil, a local address is automatically chosen.
	LocalAddr net.Addr

	// DualStack enables RFC 6555-compliant "Happy Eyeballs" dialing
	// when the network is "tcp" and the destination is a host name
	// with both IPv4 and IPv6 addresses. This allows a client to
	// tolerate networks where one address family is silently broken.
	DualStack bool

	// FallbackDelay specifies the length of time to wait before
	// spawning a fallback connection, when DualStack is enabled.
	// If zero, a default delay of 300ms is used.
	FallbackDelay time.Duration

	// KeepAlive specifies the keep-alive period for an active
	// network connection.
	// If zero, keep-alives are not enabled. Network protocols
	// that do not support keep-alives ignore this field.
	KeepAlive time.Duration

	// Cancel is an optional channel whose closure indicates that
	// the dial should be canceled. Not all types of dials support
	// cancelation.
	Cancel <-chan struct{}
}

// dialContext holds common state for all dial operations.
type dialContext struct {
	Dialer
	network, address string
	finalDeadline    time.Time
}

type addrList []net.Addr

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

func (addrs addrList) partition(strategy func(net.Addr) bool) (primaries, fallbacks addrList) {
	for _, addr := range addrs {
		if strategy(addr) {
			primaries = append(primaries, addr)
		} else {
			fallbacks = append(fallbacks, addr)
		}
	}
	return
}

// Return either now+Timeout or Deadline, whichever comes first.
// Or zero, if neither is set.
func (d *Dialer) deadline(now time.Time) time.Time {
	if d.Timeout == 0 {
		return d.Deadline
	}
	timeoutDeadline := now.Add(d.Timeout)
	if d.Deadline.IsZero() || timeoutDeadline.Before(d.Deadline) {
		return timeoutDeadline
	} else {
		return d.Deadline
	}
}

func (d *Dialer) fallbackDelay() time.Duration {
	if d.FallbackDelay > 0 {
		return d.FallbackDelay
	} else {
		return 300 * time.Millisecond
	}
}

// Dial connects to the address on the named network.
//
// See func Dial for a description of the network and address
// parameters.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	finalDeadline := d.deadline(time.Now())
	addrs, err := resolveAddrList("dial", network, address, finalDeadline)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: err}
	}

	ctx := &dialContext{
		Dialer:        *d,
		network:       network,
		address:       address,
		finalDeadline: finalDeadline,
	}

	var primaries, fallbacks addrList
	if d.DualStack && network == "tcp" {
		primaries, fallbacks = addrs.partition(isIPv4)
	} else {
		primaries = addrs
	}

	var c net.Conn
	if len(fallbacks) == 0 {
		// dialParallel can accept an empty fallbacks list,
		// but this shortcut avoids the goroutine/channel overhead.
		c, err = dialSerial(ctx, primaries, nil)
	} else {
		c, err = dialParallel(ctx, primaries, fallbacks)
	}

	return c, err
}

type dialResult struct {
	net.Conn
	error
	primary bool
}

// dialSerialAsync runs dialSerial after some delay, and returns the
// resulting connection through a channel. When racing two connections,
// the primary goroutine uses a nil timer to omit the delay.
func dialSerialAsync(ctx *dialContext, ras addrList, timer *time.Timer, cancel <-chan struct{}, results chan<- dialResult) {
	if timer != nil {
		// We're in the fallback goroutine; sleep before connecting.
		select {
		case <-timer.C:
		case <-cancel:
			return
		}
	}
	c, err := dialSerial(ctx, ras, cancel)
	select {
	case results <- dialResult{c, err, timer == nil}:
		// We won the race.

	case <-cancel:
		// The other goroutine won the race.
		if c != nil {
			c.Close()
		}
	}
}

// dialParallel races two copies of dialSerial, giving the first a
// head start. It returns the first established connection and
// closes the others. Otherwise it returns an error from the first
// primary address.
func dialParallel(ctx *dialContext, primaries, fallbacks addrList) (net.Conn, error) {
	results := make(chan dialResult) // unbuffered, so dialSerialAsync can detect race loss & cleanup
	cancel := make(chan struct{})
	defer close(cancel)

	// Spawn the primary racer.
	go dialSerialAsync(ctx, primaries, nil, cancel, results)

	// Spawn the fallback racer.
	fallbackTimer := time.NewTimer(ctx.fallbackDelay())
	go dialSerialAsync(ctx, fallbacks, fallbackTimer, cancel, results)

	var primaryErr error
	for nracers := 2; nracers > 0; nracers-- {
		res := <-results
		// If we're still waiting for a connection, then hasten the delay.
		// Otherwise, disable the Timer and let cancel take over.
		if fallbackTimer.Stop() && res.error != nil {
			fallbackTimer.Reset(0)
		}
		if res.error == nil {
			return res.Conn, nil
		}
		if res.primary {
			primaryErr = res.error
		}
	}
	return nil, primaryErr
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
