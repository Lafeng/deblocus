package tunnel

import (
	"net"
)

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
