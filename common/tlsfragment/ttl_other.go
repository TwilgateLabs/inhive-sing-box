//go:build !(linux || darwin || windows)

package tf

import "net"

// Fallback for platforms without a real TTL path (linux/darwin use ttl_unix.go,
// windows uses ttl_windows.go): disorder gracefully degrades to a plain split
// (no low-TTL first segment).
func lowerTTL(conn *net.TCPConn, ttl int) (origV4 int, origV6 int, err error) {
	return 0, 0, nil
}

func restoreTTL(conn *net.TCPConn, origV4 int, origV6 int) error {
	return nil
}
