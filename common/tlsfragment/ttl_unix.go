//go:build linux || darwin

package tf

import (
	"net"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/unix"
)

// lowerTTL sets a low IP TTL / IPv6 hop-limit on the connected socket and
// returns the original values so the caller can restore them. Used by the
// "disorder" desync: the first ClientHello segment is sent with TTL=1 so it
// expires one hop out (the DPI sees it, the server does not), then the kernel
// retransmits the same bytes with the restored TTL and the server reassembles.
// This is a plain setsockopt on a normal socket — no raw sockets — and works
// inside the iOS NetworkExtension sandbox (same control.Conn fd path that
// writeAndWaitAck already uses). Errors on individual options are tolerated
// (e.g. IP_TTL on an IPv6-only socket) so a dual-stack mismatch never kills
// the connection; restore only re-applies values we actually captured.
func lowerTTL(conn *net.TCPConn, ttl int) (origV4 int, origV6 int, err error) {
	err = control.Conn(conn, func(fd uintptr) error {
		origV4, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
		origV6, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		return nil
	})
	return
}

// restoreTTL re-applies the original TTL / hop-limit captured by lowerTTL.
// Only positive originals are restored (a non-positive value means the option
// was not readable on this socket family and must be left untouched).
func restoreTTL(conn *net.TCPConn, origV4 int, origV6 int) error {
	return control.Conn(conn, func(fd uintptr) error {
		if origV4 > 0 {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, origV4)
		}
		if origV6 > 0 {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, origV6)
		}
		return nil
	})
}
