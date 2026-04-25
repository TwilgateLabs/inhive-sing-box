package utproto

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDialLive performs a full UTProto handshake against a live server and
// pipes an HTTP request through the tunnel.
//
// Set environment variables to run:
//
//	UTPROTO_SERVER=216.173.71.34:3444  (host:port)
//	UTPROTO_SECRET=3be3d01cd333ea03802cac5cdd745b50  (32-char hex)
//	UTPROTO_DOMAIN=learn.microsoft.com  (optional, default learn.microsoft.com)
//
// When UTPROTO_SERVER is not set the test is skipped (safe for CI).
func TestDialLive(t *testing.T) {
	server := os.Getenv("UTPROTO_SERVER")
	if server == "" {
		t.Skip("set UTPROTO_SERVER=host:port to run live integration test")
	}
	if os.Getenv("UTPROTO_VLESS_UUID") != "" {
		t.Skip("server is in VLESS mode — use TestVLESSOverUTProto instead")
	}

	secretHex := os.Getenv("UTPROTO_SECRET")
	if secretHex == "" {
		t.Fatal("UTPROTO_SECRET must be set (32-char hex, no 0x prefix)")
	}

	domain := os.Getenv("UTPROTO_DOMAIN")
	if domain == "" {
		domain = "learn.microsoft.com"
	}

	// Decode secret
	raw, err := hex.DecodeString(secretHex)
	if err != nil {
		t.Fatalf("bad UTPROTO_SECRET: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("UTPROTO_SECRET must be 16 bytes (32 hex chars), got %d", len(raw))
	}

	cfg := &Config{TLSDomain: domain}
	copy(cfg.Secret[:], raw)

	// Phase 1: TCP connect
	t.Log("--- Phase 1: TCP dial ---")
	rawConn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		t.Fatalf("TCP dial to %s failed: %v", server, err)
	}
	defer rawConn.Close()
	t.Logf("TCP connected to %s", rawConn.RemoteAddr())

	// Phase 2: UTProto handshake (FakeTLS + obfuscated2)
	t.Log("--- Phase 2: UTProto handshake ---")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := Dial(ctx, rawConn, cfg)
	if err != nil {
		t.Fatalf("UTProto handshake failed: %v", err)
	}
	defer conn.Close()
	t.Log("Handshake OK — FakeTLS + obfuscated2 established")

	// Phase 3: Send HTTP request through the tunnel
	// The server pipes UTPROTO_USERS to localhost:80 (nginx), so we should
	// get an HTTP response back.
	t.Log("--- Phase 3: HTTP through tunnel ---")
	httpReq := "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		t.Fatalf("Write HTTP request: %v", err)
	}

	// Phase 4: Read response
	t.Log("--- Phase 4: Read response ---")
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			if readErr != io.EOF {
				t.Logf("Read ended with: %v", readErr)
			}
			break
		}
		if buf.Len() > 32768 {
			t.Log("Response > 32KB, truncating")
			break
		}
	}

	resp := buf.String()
	t.Logf("Got %d bytes total", len(resp))

	if len(resp) == 0 {
		t.Fatal("Empty response — tunnel may not be forwarding data")
	}

	// Show first 500 chars
	preview := resp
	if len(preview) > 500 {
		preview = preview[:500] + "..."
	}
	t.Logf("Response preview:\n%s", preview)

	// Sanity: expect some recognizable response from the pipe target.
	// UTPROTO_USERS may point to HTTP (nginx), SSH, or another TCP service.
	switch {
	case strings.HasPrefix(resp, "HTTP/"):
		t.Log("SUCCESS: Got HTTP response through UTProto tunnel")
	case strings.HasPrefix(resp, "SSH-"):
		t.Log("SUCCESS: Got SSH banner through UTProto tunnel")
	default:
		t.Logf("Got response with unknown prefix: %q (might still be valid)", resp[:min(len(resp), 60)])
	}
}

// TestGenInitHeader validates that init header generation produces valid
// output conforming to obfuscated2 constraints.
func TestGenInitHeader(t *testing.T) {
	for i := 0; i < 100; i++ {
		h, err := genInitHeader(1)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}

		// First byte must not be 0xef
		if h[0] == 0xef {
			t.Fatal("first byte is 0xef — forbidden")
		}

		// Protocol tag at [56:60] must be 0xdddddddd
		tag := uint32(h[56]) | uint32(h[57])<<8 | uint32(h[58])<<16 | uint32(h[59])<<24
		if tag != 0xdddddddd {
			t.Fatalf("protocol tag: got 0x%08x, want 0xdddddddd", tag)
		}
	}
}

// TestGenClientHello verifies that the generated ClientHello has the correct
// TLS record header and is within a reasonable size range.
func TestGenClientHello(t *testing.T) {
	cfg := &Config{TLSDomain: "www.google.com"}
	copy(cfg.Secret[:], []byte("0123456789abcdef"))

	hello, helloRand, err := generateClientHello(cfg, 1234567890)
	if err != nil {
		t.Fatalf("generateClientHello: %v", err)
	}

	// TLS record header: \x16\x03\x01
	if hello[0] != 0x16 || hello[1] != 0x03 || hello[2] != 0x01 {
		t.Fatalf("bad TLS record header: %02x %02x %02x", hello[0], hello[1], hello[2])
	}

	// Chrome with ML-KEM-768 (1184-byte key share) produces ~1800-2000 byte ClientHellos
	if len(hello) < 1500 || len(hello) > 2500 {
		t.Errorf("unexpected ClientHello length: %d (expected 1500-2500)", len(hello))
	}

	// helloRand should be 32 bytes
	if len(helloRand) != 32 {
		t.Errorf("helloRand length: %d, want 32", len(helloRand))
	}

	t.Logf("ClientHello: %d bytes, helloRand: %d bytes", len(hello), len(helloRand))
}

// TestHMACServerVerification simulates the server's HMAC check on our
// ClientHello to verify that the digest matches. This is the exact
// algorithm from mtprotoproxy's handle_fake_tls_handshake.
func TestHMACServerVerification(t *testing.T) {
	secretHex := "3be3d01cd333ea03802cac5cdd745b50"
	raw, _ := hex.DecodeString(secretHex)

	cfg := &Config{TLSDomain: "learn.microsoft.com"}
	copy(cfg.Secret[:], raw)

	unixTime := int32(time.Now().Unix())
	hello, _, err := generateClientHello(cfg, unixTime)
	if err != nil {
		t.Fatalf("generateClientHello: %v", err)
	}

	t.Logf("ClientHello: %d bytes", len(hello))
	t.Logf("First 5 bytes: %02x %02x %02x %02x %02x", hello[0], hello[1], hello[2], hello[3], hello[4])

	// Check TLS record header
	if hello[0] != 0x16 || hello[1] != 0x03 || hello[2] != 0x01 {
		t.Fatalf("bad TLS record header")
	}

	// Check record payload length
	recordLen := int(hello[3])<<8 | int(hello[4])
	t.Logf("Record payload length: %d (total %d)", recordLen, len(hello))
	if recordLen+5 != len(hello) {
		t.Errorf("record length mismatch: header says %d+5=%d, actual %d", recordLen, recordLen+5, len(hello))
	}

	// Check handshake type and length
	t.Logf("Handshake type: %02x", hello[5])
	hsLen := int(hello[6])<<16 | int(hello[7])<<8 | int(hello[8])
	t.Logf("Handshake length (uint24): %d", hsLen)

	// Check client version
	t.Logf("Client version: %02x %02x", hello[9], hello[10])

	// Extract digest from [11:43]
	digest := make([]byte, 32)
	copy(digest, hello[11:43])
	t.Logf("Digest[0:4]: %02x%02x%02x%02x", digest[0], digest[1], digest[2], digest[3])
	t.Logf("Digest[28:32]: %02x%02x%02x%02x", digest[28], digest[29], digest[30], digest[31])

	// Session ID length (at position 43)
	sessIDLen := hello[43]
	t.Logf("Session ID length: %d (at pos 43)", sessIDLen)

	// --- Simulate server HMAC check ---
	// Zero the digest slot
	msg := make([]byte, len(hello))
	copy(msg, hello)
	for i := 11; i < 43; i++ {
		msg[i] = 0
	}

	// Compute HMAC with our secret
	mac := hmac.New(sha256.New, raw)
	mac.Write(msg)
	computed := mac.Sum(nil)

	// XOR received digest with computed digest
	xored := make([]byte, 32)
	for i := 0; i < 32; i++ {
		xored[i] = digest[i] ^ computed[i]
	}

	t.Logf("XOR[0:4]: %02x%02x%02x%02x", xored[0], xored[1], xored[2], xored[3])
	t.Logf("XOR[24:28]: %02x%02x%02x%02x", xored[24], xored[25], xored[26], xored[27])
	t.Logf("XOR[28:32]: %02x%02x%02x%02x", xored[28], xored[29], xored[30], xored[31])

	// First 28 bytes must be all zeros
	allZero := true
	for i := 0; i < 28; i++ {
		if xored[i] != 0 {
			allZero = false
			t.Errorf("XOR byte %d is %02x, expected 0x00", i, xored[i])
			break
		}
	}
	if allZero {
		t.Log("HMAC first 28 bytes: all zeros ✓")
	}

	// Last 4 bytes should be the timestamp
	recovered := int32(xored[28]) | int32(xored[29])<<8 | int32(xored[30])<<16 | int32(xored[31])<<24
	t.Logf("Recovered timestamp: %d", recovered)
	t.Logf("Expected unixTime:   %d", unixTime)
	t.Logf("Difference: %d seconds", int(time.Now().Unix())-int(recovered))

	if recovered != unixTime {
		t.Errorf("timestamp mismatch: got %d, want %d", recovered, unixTime)
	} else {
		t.Log("Timestamp matches ✓")
	}

	// Check server would accept time skew
	skew := float64(time.Now().Unix()) - float64(recovered)
	if skew < -20*60 || skew > 10*60 {
		t.Errorf("time skew %.0f seconds — server would reject", skew)
	} else {
		t.Logf("Time skew: %.0f seconds — within acceptable range ✓", skew)
	}

	// Check record length > 512 (server rejects smaller)
	if recordLen < 512 {
		t.Errorf("Record payload length %d < 512 — server would reject as non-TLS", recordLen)
	} else {
		t.Logf("Record length %d > 512 ✓", recordLen)
	}
}

// TestVLESSOverUTProto performs the full chain test:
//
//	Client → UTProto FakeTLS (:3444) → VLESS-TCP-plain (127.0.0.1:19999) → internet
//
// It sends a VLESS protocol header with a TCP connect command to example.com:80,
// then pipes an HTTP request and reads the response.
//
// Environment variables (same as TestDialLive plus VLESS UUID):
//
//	UTPROTO_SERVER=216.173.71.34:3444
//	UTPROTO_SECRET=3be3d01cd333ea03802cac5cdd745b50
//	UTPROTO_VLESS_UUID=761bb14f-51aa-49b6-b583-37ea11132568
//
// When UTPROTO_SERVER is not set the test is skipped.
func TestVLESSOverUTProto(t *testing.T) {
	server := os.Getenv("UTPROTO_SERVER")
	if server == "" {
		t.Skip("set UTPROTO_SERVER=host:port to run live integration test")
	}

	secretHex := os.Getenv("UTPROTO_SECRET")
	if secretHex == "" {
		t.Fatal("UTPROTO_SECRET must be set")
	}

	uuidStr := os.Getenv("UTPROTO_VLESS_UUID")
	if uuidStr == "" {
		t.Fatal("UTPROTO_VLESS_UUID must be set (e.g. 761bb14f-51aa-49b6-b583-37ea11132568)")
	}

	domain := os.Getenv("UTPROTO_DOMAIN")
	if domain == "" {
		domain = "learn.microsoft.com"
	}

	// Parse secret
	raw, err := hex.DecodeString(secretHex)
	if err != nil {
		t.Fatalf("bad UTPROTO_SECRET: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("UTPROTO_SECRET must be 16 bytes (32 hex chars), got %d", len(raw))
	}

	// Parse UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx → 16 bytes)
	uuidHex := strings.ReplaceAll(uuidStr, "-", "")
	uuidBytes, err := hex.DecodeString(uuidHex)
	if err != nil {
		t.Fatalf("bad UTPROTO_VLESS_UUID: %v", err)
	}
	if len(uuidBytes) != 16 {
		t.Fatalf("UUID must be 16 bytes, got %d", len(uuidBytes))
	}

	cfg := &Config{TLSDomain: domain}
	copy(cfg.Secret[:], raw)

	// Phase 1: UTProto tunnel
	t.Log("--- Phase 1: UTProto handshake ---")
	rawConn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		t.Fatalf("TCP dial to %s failed: %v", server, err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := Dial(ctx, rawConn, cfg)
	if err != nil {
		t.Fatalf("UTProto handshake failed: %v", err)
	}
	defer conn.Close()
	t.Log("UTProto tunnel established")

	// Phase 2: Send VLESS protocol header
	// Format: [version:1][UUID:16][addons_len:1][command:1][port:2][addr_type:1][addr]
	t.Log("--- Phase 2: VLESS header ---")
	target := "example.com"
	targetPort := uint16(80)

	var vlessHeader []byte
	vlessHeader = append(vlessHeader, 0x00)           // version
	vlessHeader = append(vlessHeader, uuidBytes...)    // UUID (16 bytes)
	vlessHeader = append(vlessHeader, 0x00)           // addons length (none)
	vlessHeader = append(vlessHeader, 0x01)           // command: TCP connect
	vlessHeader = append(vlessHeader, byte(targetPort>>8), byte(targetPort)) // port big-endian
	vlessHeader = append(vlessHeader, 0x02)           // address type: domain
	vlessHeader = append(vlessHeader, byte(len(target))) // domain length
	vlessHeader = append(vlessHeader, []byte(target)...) // domain

	t.Logf("VLESS header: %d bytes → %s:%d", len(vlessHeader), target, targetPort)

	// Phase 3: Send VLESS header + HTTP request in one write
	// VLESS is stream-based — first write includes the header,
	// subsequent data flows transparently.
	t.Log("--- Phase 3: HTTP request through VLESS ---")
	httpReq := "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"

	// Combine VLESS header + HTTP request into single payload
	payload := append(vlessHeader, []byte(httpReq)...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write VLESS+HTTP: %v", err)
	}
	t.Log("Sent VLESS header + HTTP request")

	// Phase 4: Read VLESS response header + HTTP response
	// VLESS server sends: [version:1][addons_len:1][addons...] then proxied data
	t.Log("--- Phase 4: Read response ---")

	// Set read deadline
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Read VLESS response header first (2 bytes minimum: version + addons_len)
	respHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		t.Fatalf("Read VLESS response header: %v", err)
	}
	t.Logf("VLESS response: version=%d, addons_len=%d", respHeader[0], respHeader[1])

	// Skip addons if any
	if respHeader[1] > 0 {
		addons := make([]byte, respHeader[1])
		if _, err := io.ReadFull(conn, addons); err != nil {
			t.Fatalf("Read VLESS addons: %v", err)
		}
	}

	// Now read the proxied HTTP response
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			if readErr != io.EOF {
				t.Logf("Read ended with: %v", readErr)
			}
			break
		}
		if buf.Len() > 32768 {
			t.Log("Response > 32KB, truncating")
			break
		}
	}

	resp := buf.String()
	t.Logf("Got %d bytes of HTTP response", len(resp))

	if len(resp) == 0 {
		t.Fatal("Empty HTTP response — VLESS tunnel may not be working")
	}

	// Show first 500 chars
	preview := resp
	if len(preview) > 500 {
		preview = preview[:500] + "..."
	}
	t.Logf("Response preview:\n%s", preview)

	// Validate HTTP response
	if !strings.HasPrefix(resp, "HTTP/") {
		t.Fatalf("Expected HTTP response, got: %q", resp[:min(len(resp), 80)])
	}

	t.Log("SUCCESS: Got HTTP response through UTProto → VLESS → internet chain")

	// Extra validation: check for expected example.com content
	if strings.Contains(resp, "Example Domain") {
		t.Log("Confirmed: response is from example.com ✓")
	} else if strings.Contains(resp, "200 OK") || strings.Contains(resp, "200") {
		t.Log("Got HTTP 200 response ✓")
	}
}

// TestDialAcceptRoundTrip exercises the full client↔server handshake
// in-process: Dial from one goroutine, Accept on a loopback listener
// from another, exchange a message over the established obf2 stream,
// and verify the server correctly identifies the matching user from a
// pool of fake users.
func TestDialAcceptRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Build a pool of 5 users with random secrets; the "real" secret
	// sits in the middle so we prove the multi-user loop actually
	// iterates (not just returns users[0]).
	users := make([]ServerUser, 5)
	for i := range users {
		if _, err := io.ReadFull(rand.Reader, users[i].Secret[:]); err != nil {
			t.Fatal(err)
		}
		users[i].Name = "fake_" + string(rune('a'+i))
	}
	var realSecret [16]byte
	if _, err := io.ReadFull(rand.Reader, realSecret[:]); err != nil {
		t.Fatal(err)
	}
	users[2].Secret = realSecret
	users[2].Name = "real_user"

	serverErr := make(chan error, 1)
	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer rawConn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, user, err := Accept(ctx, rawConn, users)
		if err != nil {
			serverErr <- err
			return
		}
		if user.Name != "real_user" {
			serverErr <- errors.New("wrong user matched: " + user.Name)
			return
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	cfg := &Config{TLSDomain: "learn.microsoft.com", Secret: realSecret}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, rawConn, cfg)
	if err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello utproto — round trip")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server goroutine did not finish")
	}
}

// TestAcceptWrongSecret verifies that Accept rejects connections whose
// HMAC does not match any configured user secret.
func TestAcceptWrongSecret(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var serverSecret [16]byte
	copy(serverSecret[:], []byte("server_secret_16"))
	users := []ServerUser{{Name: "srv", Secret: serverSecret}}

	serverDone := make(chan *HandshakeError, 1)
	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			serverDone <- &HandshakeError{Kind: "accept_failed", Err: err}
			return
		}
		defer rawConn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err = Accept(ctx, rawConn, users)
		var he *HandshakeError
		if errors.As(err, &he) {
			serverDone <- he
		} else {
			serverDone <- nil
		}
	}()

	var clientSecret [16]byte
	copy(clientSecret[:], []byte("client_secret_16"))
	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	cfg := &Config{TLSDomain: "learn.microsoft.com", Secret: clientSecret}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = Dial(ctx, rawConn, cfg) // expected to fail or hang

	select {
	case he := <-serverDone:
		if he == nil {
			t.Fatal("server accepted wrong secret (expected HandshakeError)")
		}
		if he.Kind != "identify_user" {
			t.Fatalf("wrong HandshakeError Kind: got %q want identify_user", he.Kind)
		}
		if len(he.Buffer) < 500 {
			t.Errorf("expected buffered ClientHello bytes for fallback replay, got %d", len(he.Buffer))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not reject handshake")
	}
}
