//go:build windows

package tf

import (
	"net"
	"os"
	"time"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/windows"
)

// TransmitFile flags (not exported by x/sys/windows).
const (
	tfUseKernelAPC = 0x20 // TF_USE_KERNEL_APC
	tfWriteBehind  = 0x04 // TF_WRITE_BEHIND
)

// sendFake performs byedpi's "fake" desync on Windows: send `fake` (a ClientHello
// whose SNI is a benign placeholder) over the socket at a low TTL so it expires
// one hop out — the on-path DPI records the benign SNI for this flow and won't
// throttle/RST it — then overwrite the backing file with `real` so the kernel
// retransmit (the low-TTL segment is never ACKed) re-reads and delivers the REAL
// ClientHello to the server. Mirrors byedpi's win send_fake (TransmitFile,
// async TF_WRITE_BEHIND, file content swapped under the in-flight send).
//
// ran=true → the fake path executed and the real ClientHello is delivered by the
// retransmit (caller must NOT also write it). ran=false → unsupported/failed,
// caller falls back to a normal write.
//
// NOTE: this drives TransmitFile on a socket fd that Go's netpoller (IOCP) also
// owns — if that conflicts in the Go runtime it will surface as broken
// handshakes in testing; this is the empirical gate for fake-in-Go.
func sendFake(conn *net.TCPConn, real, fake []byte, ttl int, delay time.Duration) (ran bool, err error) {
	if len(fake) == 0 || len(real) == 0 {
		return false, nil
	}
	f, ferr := os.CreateTemp("", "ih-fake-*.bin")
	if ferr != nil {
		return false, nil // can't fake → fall back
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	if _, werr := f.Write(fake); werr != nil {
		return false, nil
	}
	fh := windows.Handle(f.Fd())

	cerr := control.Conn(conn, func(fd uintptr) error {
		s := windows.Handle(fd)
		// Lower TTL so the fake segment dies before the server.
		_ = windows.SetsockoptInt(s, winIPPROTO_IP, winIP_TTL, ttl)
		_ = windows.SetsockoptInt(s, winIPPROTO_IPV6, winIPV6_UNICAST_HOPS, ttl)

		_, _ = windows.SetFilePointer(fh, 0, nil, windows.FILE_BEGIN)
		ev, eerr := windows.CreateEvent(nil, 1, 0, nil)
		if eerr != nil {
			_ = windows.SetsockoptInt(s, winIPPROTO_IP, winIP_TTL, winDefaultTTL)
			return eerr
		}
		ov := &windows.Overlapped{HEvent: ev}
		terr := windows.TransmitFile(s, fh, uint32(len(fake)), uint32(len(fake)), ov, nil, tfUseKernelAPC|tfWriteBehind)
		if terr != nil && terr != windows.ERROR_IO_PENDING {
			windows.CloseHandle(ev)
			_ = windows.SetsockoptInt(s, winIPPROTO_IP, winIP_TTL, winDefaultTTL)
			return terr
		}
		// Swap the file content to REAL so the kernel retransmit carries it.
		_, _ = windows.SetFilePointer(fh, 0, nil, windows.FILE_BEGIN)
		var wrote uint32
		_ = windows.WriteFile(fh, real, &wrote, nil)
		// Restore TTL so the retransmit reaches the server.
		_ = windows.SetsockoptInt(s, winIPPROTO_IP, winIP_TTL, winDefaultTTL)
		_ = windows.SetsockoptInt(s, winIPPROTO_IPV6, winIPV6_UNICAST_HOPS, winDefaultTTL)
		ran = true
		windows.CloseHandle(ev)
		return nil
	})
	// The temp file must outlive the in-flight async send; sleep before the
	// deferred close/remove.
	if delay <= 0 {
		delay = 300 * time.Millisecond
	}
	time.Sleep(delay)
	if cerr != nil {
		return false, cerr
	}
	return ran, nil
}
