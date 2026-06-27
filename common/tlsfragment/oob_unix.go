//go:build linux || darwin

package tf

import (
	"net"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/unix"
)

// sendOOB writes payload followed by a single out-of-band (urgent) byte using
// send(MSG_OOB) on the connected socket — the userspace "oob" desync. The
// urgent byte stands in for the real boundary byte (which is re-sent at the head
// of the next segment); a DPI that folds urgent data into the in-band stream
// mis-parses the SNI, while the server (urgent byte delivered out-of-band by
// default) still reassembles the real ClientHello. Plain send on a normal fd —
// no raw sockets — same control.Conn(fd) path as lowerTTL, so it works inside
// the iOS NetworkExtension sandbox. Returns the count of real (in-band) bytes.
func sendOOB(conn *net.TCPConn, payload []byte, oob byte) (int, error) {
	buf := make([]byte, len(payload)+1)
	copy(buf, payload)
	buf[len(payload)] = oob
	err := control.Conn(conn, func(fd uintptr) error {
		return unix.Send(int(fd), buf, unix.MSG_OOB)
	})
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}
