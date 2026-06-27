//go:build !(linux || darwin)

package tf

import "net"

// Platforms without the unix TTL path (notably Windows): disorder gracefully
// degrades to a plain split (no low-TTL first segment). Windows can be wired
// later via winsock IP_TTL; the priority targets for the accelerator are
// Android (linux) and iOS (darwin), which use ttl_unix.go.
func lowerTTL(conn *net.TCPConn, ttl int) (origV4 int, origV6 int, err error) {
	return 0, 0, nil
}

func restoreTTL(conn *net.TCPConn, origV4 int, origV6 int) error {
	return nil
}
