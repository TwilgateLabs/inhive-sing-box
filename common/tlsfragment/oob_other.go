//go:build !(linux || darwin || windows)

package tf

import "net"

// sendOOB has no MSG_OOB path on this platform, so the oob/disoob desync
// degrades to a plain segment write (the urgent-byte trick is dropped) — the
// same graceful degradation ttl_other.go applies to disorder.
func sendOOB(conn *net.TCPConn, payload []byte, oob byte) (int, error) {
	return conn.Write(payload)
}
