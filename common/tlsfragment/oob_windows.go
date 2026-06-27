//go:build windows

package tf

import (
	"net"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/windows"
)

// sendOOB writes payload followed by a single out-of-band (urgent) byte using
// WSASend with MSG_OOB on the connected winsock — the userspace "oob" desync
// (see oob_unix.go for the mechanism). x/sys/windows exposes no plain send(), so
// we use WSASend with a single buffer; same control.Conn(fd) path as lowerTTL.
// Returns the count of real (in-band) bytes.
func sendOOB(conn *net.TCPConn, payload []byte, oob byte) (int, error) {
	buf := make([]byte, len(payload)+1)
	copy(buf, payload)
	buf[len(payload)] = oob
	var sent uint32
	err := control.Conn(conn, func(fd uintptr) error {
		wsaBuf := windows.WSABuf{Len: uint32(len(buf)), Buf: &buf[0]}
		return windows.WSASend(windows.Handle(fd), &wsaBuf, 1, &sent, windows.MSG_OOB, nil, nil)
	})
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}
