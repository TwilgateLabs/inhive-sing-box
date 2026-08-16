//go:build with_olcrtc

package olcrtc

// Liveness coverage for the olcrtc outbound — everything OUR adapter owns,
// hermetically (loopback only).
//
// HONEST SCOPE NOTE: a full traffic gate (WebRTC data channel through an SFU
// room) is NOT possible from this module: the server half of the tunnel lives
// in `internal/` of the TwilgateLabs/inhive-olcrtc fork (unimportable from
// here), and the transport requires a live SFU with websocket signaling plus a
// remote peer — there is nothing to spin up in-process. That end-to-end gate
// belongs to the fork's own e2e suite. What we CAN and DO prove here:
//
//  1. option validation (required fields, UUID/hex formats, SEC-2 transport
//     pin, SEC-3 DNS default) — the config surface a refactoring breaks first;
//  2. the lazy non-primary lifecycle contract (Start returns instantly with no
//     network, Close never hangs on a never-dialed outbound) — the anti-phantom
//     invariant the box start depends on;
//  3. the SOCKS5 detour plumbing CARRIES REAL BYTES: DialContext → sing socks
//     client → loopback SOCKS5 server (standing in for client.Run's listener)
//     → destination, echo verified. Everything in outbound.go except
//     client.Run itself is on that path.
//
// Uncovered and known: pkg/olcrtc/client.Run (carrier join, muxconn, smux) —
// vendored fork code, exercised only by the fork's e2e and by field use.

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	olcrtcTestChannelID = "12345678-1234-4123-8123-123456789abc"
	olcrtcTestKeyHex    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

func olcrtcTestLogger() log.ContextLogger {
	return log.NewNOPFactory().Logger()
}

func olcrtcValidOptions() option.OLCRTCOutboundOptions {
	return option.OLCRTCOutboundOptions{
		Carrier:   "jitsi",
		RoomURL:   "https://meet.example.org/room",
		ChannelID: olcrtcTestChannelID,
		KeyHex:    olcrtcTestKeyHex,
	}
}

// TestNewOutbound_Validation locks the config-parse contract: required fields,
// format checks, and the SEC-2/SEC-3 hardening pins. A refactoring that
// loosens any of these (e.g. re-admits video transports) goes red here.
func TestNewOutbound_Validation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*option.OLCRTCOutboundOptions)
		wantErr string
	}{
		{"missing carrier", func(o *option.OLCRTCOutboundOptions) { o.Carrier = "" }, "carrier is required"},
		{"missing room_url", func(o *option.OLCRTCOutboundOptions) { o.RoomURL = "" }, "room_url is required"},
		{"missing channel_id", func(o *option.OLCRTCOutboundOptions) { o.ChannelID = "" }, "channel_id is required"},
		{"non-uuid channel_id", func(o *option.OLCRTCOutboundOptions) { o.ChannelID = "not-a-uuid" }, "must be a UUID"},
		{"missing key_hex", func(o *option.OLCRTCOutboundOptions) { o.KeyHex = "" }, "key_hex is required"},
		{"short key_hex", func(o *option.OLCRTCOutboundOptions) { o.KeyHex = "abcd" }, "64 hex chars"},
		{"SEC-2 video transport blocked", func(o *option.OLCRTCOutboundOptions) { o.Transport = "vp8channel" }, "not permitted"},
		{"SEC-3 malformed dns_server", func(o *option.OLCRTCOutboundOptions) { o.DNSServer = "no-port" }, "host:port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := olcrtcValidOptions()
			tc.mutate(&opts)
			_, err := NewOutbound(context.Background(), nil, olcrtcTestLogger(), "olcrtc-test", opts)
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}

	// The valid baseline must construct (no network happens in NewOutbound).
	ob, err := NewOutbound(context.Background(), nil, olcrtcTestLogger(), "olcrtc-test", olcrtcValidOptions())
	if err != nil {
		t.Fatalf("valid options must construct: %v", err)
	}
	o := ob.(*Outbound)
	defer o.runCancel()
	if o.cfg.DNSServer != defaultDNSServer {
		t.Fatalf("SEC-3 default DNS not applied: got %q want %q", o.cfg.DNSServer, defaultDNSServer)
	}
	if o.cfg.Transport != allowedTransport {
		t.Fatalf("SEC-2 transport pin not applied: got %q", o.cfg.Transport)
	}
}

// TestLazyNonPrimaryLifecycle locks the Вариант-C contract: a non-primary
// outbound must Start instantly with ZERO network activity and Close without
// waiting — a dead pool member must never stall box bring-up or teardown.
func TestLazyNonPrimaryLifecycle(t *testing.T) {
	ob, err := NewOutbound(context.Background(), nil, olcrtcTestLogger(), "olcrtc-lazy", olcrtcValidOptions())
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	o := ob.(*Outbound)

	started := time.Now()
	if err := o.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("lazy Start must return nil, got: %v", err)
	}
	if d := time.Since(started); d > time.Second {
		t.Fatalf("lazy Start took %s — must be instant (no join on start)", d)
	}

	closed := time.Now()
	if err := o.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(closed); d > time.Second {
		t.Fatalf("Close of a never-dialed lazy outbound took %s — must not wait for runDone", d)
	}
}

// startTestSocks5Server runs a minimal no-auth SOCKS5 CONNECT server on
// loopback, standing in for the listener client.Run opens in production. It
// dials the requested destination (loopback only — hermetic guard) and pipes.
func startTestSocks5Server(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Greeting: VER NMETHODS METHODS...
				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x05 {
					return
				}
				methods := make([]byte, int(head[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no auth
					return
				}
				// Request: VER CMD RSV ATYP ...
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil || req[1] != 0x01 {
					return
				}
				var host string
				switch req[3] {
				case 0x01: // IPv4
					a := make([]byte, 4)
					if _, err := io.ReadFull(c, a); err != nil {
						return
					}
					host = net.IP(a).String()
				case 0x03: // domain
					l := make([]byte, 1)
					if _, err := io.ReadFull(c, l); err != nil {
						return
					}
					d := make([]byte, int(l[0]))
					if _, err := io.ReadFull(c, d); err != nil {
						return
					}
					host = string(d)
				default:
					return
				}
				var portBytes [2]byte
				if _, err := io.ReadFull(c, portBytes[:]); err != nil {
					return
				}
				port := binary.BigEndian.Uint16(portBytes[:])
				dst := net.JoinHostPort(host, itoa(port))
				// Hermetic guard: only loopback destinations are dialed.
				if !strings.HasPrefix(host, "127.") && host != "localhost" {
					return
				}
				upstream, err := net.DialTimeout("tcp", dst, 5*time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				done := make(chan struct{}, 2)
				go func() { io.Copy(upstream, c); done <- struct{}{} }()
				go func() { io.Copy(c, upstream); done <- struct{}{} }()
				<-done
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func itoa(p uint16) string {
	b := [5]byte{}
	i := len(b)
	for {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
		if p == 0 {
			break
		}
	}
	return string(b[i:])
}

// TestSocksDetourCarriesTraffic proves the outbound's data path carries real
// bytes: DialContext → sing socks.Client → loopback SOCKS5 (stand-in for
// client.Run's listener) → destination echo server, payload verified both
// ways. This is every line of OUR plumbing in outbound.go except client.Run
// itself (see the scope note in the file header).
func TestSocksDetourCarriesTraffic(t *testing.T) {
	// Echo destination.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	socksAddr := startTestSocks5Server(t)

	opts := olcrtcValidOptions()
	opts.SocksAddr = socksAddr // non-zero port → used verbatim
	ob, err := NewOutbound(context.Background(), nil, olcrtcTestLogger(), "olcrtc-detour", opts)
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	o := ob.(*Outbound)

	// White-box: mark the client as already running+ready so DialContext takes
	// the SOCKS5 path instead of launching a real WebRTC join (which would need
	// a live SFU — see scope note). The stand-in SOCKS5 server above plays the
	// role of client.Run's local listener.
	o.runMu.Lock()
	o.launched = true
	o.runMu.Unlock()
	o.onReady()
	o.socksDialer = o.newSocksDialer()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr(echoLn.Addr().String()))
	if err != nil {
		t.Fatalf("DialContext through SOCKS5 detour: %v", err)
	}
	defer conn.Close()

	payload := []byte("olcrtc socks detour round trip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	// UDP must be refused explicitly (WebRTC data channel is stream-only).
	if _, err := o.ListenPacket(ctx, M.ParseSocksaddr(echoLn.Addr().String())); err == nil {
		t.Fatal("ListenPacket must be refused on olcrtc outbound")
	}

	// Unblock Close(): the run goroutine was never launched, so runDone would
	// never close — release it manually before the lifecycle teardown.
	close(o.runDone)
	if err := o.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
