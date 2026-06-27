package tf_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	tf "github.com/sagernet/sing-box/common/tlsfragment"

	"github.com/stretchr/testify/require"
)

func TestTLSFragment(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), true, false, false, false, false, 0, "", 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}

func TestTLSRecordFragment(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), false, true, false, false, false, 0, "", 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}

func TestTLS2Fragment(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), true, true, false, false, false, 0, "", 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}

func TestTLSDisorder(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), false, false, true, false, false, 0, "", 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}

// TestTLSSplitPosition exercises an explicit byedpi-style split position: split
// the ClientHello one byte into the SNI. This is a precise TCP-segment split (no
// urgent byte), so a compliant server still completes the handshake.
func TestTLSSplitPosition(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), true, false, false, false, false, 1, "sni", 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}

// oob/disoob correctness is proven deterministically by TestOOBLocalStrip
// (oob_test.go). A successful handshake CANNOT be asserted against real CDNs:
// modern servers following RFC 6093 (Cloudflare/Google) deliver urgent data
// inline, leaving the fake byte in the ClientHello and breaking the handshake.
// These two cases therefore only smoke-test that the full NewConn -> Write ->
// segment-loop -> sendOOB path runs against a real socket without panicking or
// hanging (the handshake error is expected and ignored).
func TestTLSOOB(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), false, false, false, true, false, 0, "", 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	_ = tlsConn.Handshake()
}

func TestTLSDisOOB(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), false, false, false, false, true, 0, "", 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	_ = tlsConn.Handshake()
}
