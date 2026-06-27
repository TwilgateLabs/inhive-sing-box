//go:build !windows

package tf

import (
	"net"
	"time"
)

// sendFake is Windows-only for now (the TransmitFile retransmit-swap). On other
// platforms the "fake" desync is unsupported, so the caller falls back to a
// normal write. Android (vmsplice+splice retransmit-swap) is a planned follow-up.
func sendFake(conn *net.TCPConn, real, fake []byte, ttl int, delay time.Duration) (bool, error) {
	return false, nil
}
