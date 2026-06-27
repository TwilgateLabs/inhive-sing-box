//go:build windows

package tf

import (
	"net"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/windows"
)

// Winsock socket-option numbers (stable ABI values; not all are exported by
// x/sys/windows, so we spell them out).
const (
	winIPPROTO_IP        = 0
	winIP_TTL            = 7
	winIPPROTO_IPV6      = 41
	winIPV6_UNICAST_HOPS = 4
	// Restore target: Windows' default unicast TTL is 128. x/sys/windows has no
	// GetsockoptInt, so instead of reading the original we re-raise to the OS
	// default after the low-TTL first segment — adequate, since that is the
	// value the socket carried before lowerTTL.
	winDefaultTTL = 128
)

// lowerTTL sets a low IP TTL / IPv6 hop-limit on the connected socket via
// winsock setsockopt for the "disorder" desync: the first ClientHello segment
// egresses at TTL=1 so it expires one hop out (the on-path DPI sees it, the
// server never does), then the kernel retransmits the same bytes at the
// restored TTL and the server reassembles a stream the DPI saw out of order.
// Plain setsockopt on a normal socket — same control.Conn(fd) path as
// writeAndWaitAck, no raw sockets. Per-option errors are tolerated so a
// dual-stack mismatch never kills the connection. Returns winDefaultTTL as the
// "original" for restoreTTL to re-apply (x/sys/windows lacks GetsockoptInt).
func lowerTTL(conn *net.TCPConn, ttl int) (origV4 int, origV6 int, err error) {
	err = control.Conn(conn, func(fd uintptr) error {
		h := windows.Handle(fd)
		_ = windows.SetsockoptInt(h, winIPPROTO_IP, winIP_TTL, ttl)
		_ = windows.SetsockoptInt(h, winIPPROTO_IPV6, winIPV6_UNICAST_HOPS, ttl)
		return nil
	})
	return winDefaultTTL, winDefaultTTL, err
}

// restoreTTL re-raises the TTL / hop-limit after the low-TTL first segment.
func restoreTTL(conn *net.TCPConn, origV4 int, origV6 int) error {
	return control.Conn(conn, func(fd uintptr) error {
		h := windows.Handle(fd)
		if origV4 > 0 {
			_ = windows.SetsockoptInt(h, winIPPROTO_IP, winIP_TTL, origV4)
		}
		if origV6 > 0 {
			_ = windows.SetsockoptInt(h, winIPPROTO_IPV6, winIPV6_UNICAST_HOPS, origV6)
		}
		return nil
	})
}
