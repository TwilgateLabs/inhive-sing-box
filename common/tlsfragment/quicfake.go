package tf

import (
	_ "embed"
	"net"
	"sync/atomic"
)

// quicFakePayload is a captured benign QUIC Initial (www.google.com) used as the
// fake datagram. byte 0 = 0xc3 (long header, Initial). Sourced from the zapret
// project (quic_initial_www_google_com.bin).
//
//go:embed quic_fake_payload.bin
var quicFakePayload []byte

// QUICFakeConn wraps a UDP PacketConn for the accelerator's fake-QUIC desync:
// right before forwarding the first real datagram (the QUIC Initial that carries
// the ClientHello/SNI), it injects N copies of [quicFakePayload] — a benign-SNI
// QUIC Initial — to the same destination. The server discards the fakes (unknown
// DCID / invalid crypto) but an on-path DPI records the benign SNI and won't
// throttle/RST the real flow.
//
// Unlike TCP fake (which needs raw seqovl/badseq → kernel/WinDivert), this is
// pure userspace — just extra sendto on a normal UDP socket — so it works on
// EVERY platform INCLUDING iOS (the Network Extension allows UDP datagrams; no
// raw socket required). This conn is created only for accelerator UDP:443 flows
// matched by route, so the first datagram is the QUIC Initial.
type QUICFakeConn struct {
	net.PacketConn
	repeats int
	first   atomic.Bool
}

const defaultQUICFakeRepeats = 6

func NewQUICFakeConn(conn net.PacketConn, repeats int) net.PacketConn {
	if repeats <= 0 {
		repeats = defaultQUICFakeRepeats
	}
	return &QUICFakeConn{PacketConn: conn, repeats: repeats}
}

func (c *QUICFakeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(quicFakePayload) > 0 && !c.first.Swap(true) {
		for i := 0; i < c.repeats; i++ {
			_, _ = c.PacketConn.WriteTo(quicFakePayload, addr)
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}
