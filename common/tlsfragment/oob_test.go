package tf

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestOOBLocalStrip proves sendOOB emits a real TCP urgent byte: against a
// default receiver (SO_OOBINLINE off) the trailing out-of-band byte is stripped
// from the in-band stream, so the peer reads only the real payload. This is the
// deterministic correctness check for the oob/disoob desync.
//
// NOTE on real CDNs: oob's *handshake* correctness depends on the destination
// honoring TCP urgent data this way. Modern servers following RFC 6093 (e.g.
// Cloudflare/Google frontends) deliver urgent data inline instead, which leaves
// the fake byte in the ClientHello and breaks the handshake. So oob/disoob is a
// per-site/opt-in strategy (the strategy tester selects it where it works), NOT
// a safe default — the robust defaults stay split/disorder/tls-record-fragment.
func TestOOBLocalStrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			received <- "accept-error"
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	tcpConn, ok := conn.(*net.TCPConn)
	require.True(t, ok)

	n, err := sendOOB(tcpConn, []byte("HELLO"), 'X')
	require.NoError(t, err)
	require.Equal(t, 5, n) // count of real (in-band) bytes, urgent byte excluded
	_ = conn.Close()

	// 'X' is the urgent byte and must NOT appear in the peer's normal stream.
	require.Equal(t, "HELLO", <-received)
}
