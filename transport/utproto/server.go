package utproto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Accept reads the UTProto handshake from rawConn, authenticates the
// client against one of the configured per-user secrets, and returns a
// net.Conn carrying application data plus the matched user identity.
//
// Handshake flow (mirrors Dial in reverse):
//
//  1. Read TLS record \x16\x03\x01 <len:uint16> + ClientHello body
//  2. Try each users[i].Secret: zero digest slot, HMAC-SHA256, compare
//     first 28 bytes; on match recover unix timestamp from last 4 bytes
//     and check time skew
//  3. Echo client session_id in our ServerHello
//  4. Write 3-record response: ServerHello + CCS + AppData padding.
//     Digest slot at overall buffer offset [11:43] = HMAC(secret,
//     client_rand || response_with_digest_zeroed)
//  5. Read client ChangeCipherSpec (\x14\x03\x03\x00\x01\x01)
//  6. Wrap rawConn in FakeTLS record framer
//  7. Read 64-byte obfuscated2 init header through framer
//  8. Derive AES-256-CTR keys (dec from wireHeader, enc from reversed
//     wireHeader), decrypt 64-byte header to advance dec CTR to 64 and
//     verify protocol tag 0xdddddddd at [56:60]
//  9. Return obfConn wrapping framer
//
// On failure Accept returns a *HandshakeError whose Buffer field holds
// the raw bytes already consumed from rawConn. Callers may replay them
// to a fallback TLS origin (real learn.microsoft.com:443) so a passive
// DPI scan sees a complete handshake instead of a closed connection.
//
// users must be non-empty. Per-handshake cost is O(len(users)) HMAC
// computations — negligible at hundreds of users (~1ms at 1k).
func Accept(ctx context.Context, rawConn net.Conn, users []ServerUser) (net.Conn, *ServerUser, error) {
	if len(users) == 0 {
		return nil, nil, errors.New("utproto: no users configured")
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(dl)
		defer rawConn.SetDeadline(time.Time{})
	}

	clientHello, err := readClientHello(rawConn)
	if err != nil {
		return nil, nil, &HandshakeError{Kind: "read_client_hello", Err: err, Buffer: clientHello}
	}

	user, clientRand, err := identifyUser(clientHello, users)
	if err != nil {
		return nil, nil, &HandshakeError{Kind: "identify_user", Err: err, Buffer: clientHello}
	}

	if len(clientHello) < 76 || clientHello[43] != 0x20 {
		return nil, nil, &HandshakeError{Kind: "parse_client_hello", Err: errBadClientHello, Buffer: clientHello}
	}
	sessionID := make([]byte, 32)
	copy(sessionID, clientHello[44:76])

	if err := writeServerHello(rawConn, user.Secret, clientRand, sessionID); err != nil {
		return nil, nil, &HandshakeError{Kind: "write_server_hello", Err: err, Buffer: clientHello}
	}

	var ccs [6]byte
	if _, err := io.ReadFull(rawConn, ccs[:]); err != nil {
		return nil, nil, &HandshakeError{Kind: "read_ccs", Err: err, Buffer: clientHello}
	}
	wantCCS := [6]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	if ccs != wantCCS {
		return nil, nil, &HandshakeError{Kind: "bad_ccs", Err: errors.New("utproto: bad client ccs"), Buffer: clientHello}
	}

	framer := newFakeTLSConn(rawConn)

	var wireHeader [initHeaderSize]byte
	if _, err := io.ReadFull(framer, wireHeader[:]); err != nil {
		return nil, nil, &HandshakeError{Kind: "read_obf_header", Err: err, Buffer: clientHello}
	}

	conn, err := newObfConnServer(framer, wireHeader, user.Secret)
	if err != nil {
		return nil, nil, &HandshakeError{Kind: "obf_setup", Err: err, Buffer: clientHello}
	}

	return conn, user, nil
}

// ServerUser pairs a human-readable name with a 16-byte UTProto secret.
// Multiple users can authenticate against the same inbound; Accept
// resolves identity by trying each secret against the ClientHello HMAC.
type ServerUser struct {
	Name   string
	Secret [16]byte
}

// HandshakeError wraps failures during Accept. Buffer contains bytes
// already consumed from the underlying connection so the caller can
// forward them to a fallback TLS origin for DPI evasion.
type HandshakeError struct {
	Kind   string
	Err    error
	Buffer []byte
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("utproto handshake %s: %v", e.Kind, e.Err)
}

func (e *HandshakeError) Unwrap() error { return e.Err }

// newObfConnServer mirrors newObfConn (see obfuscated.go) for the
// server side. dec is derived from wireHeader[8:40] (same inputs as
// client's enc derivation), enc is derived from reversed wireHeader
// (same inputs as client's dec). Decrypting the full 64-byte header
// advances dec CTR to position 64, keeping it synced with client's
// enc CTR at 64. The encrypted bytes [56:60] must decode to the
// obfuscated2 intermediate protocol tag 0xdddddddd — mismatch means
// the shared secret was wrong (should not happen because HMAC already
// verified the secret; guard is defensive).
func newObfConnServer(rawConn net.Conn, wireHeader [initHeaderSize]byte, secret [16]byte) (*obfConn, error) {
	decKey, decIV := deriveKey(wireHeader[:], secret)
	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	decStream := cipher.NewCTR(decBlock, decIV)

	var decrypted [initHeaderSize]byte
	decStream.XORKeyStream(decrypted[:], wireHeader[:])

	tag := binary.LittleEndian.Uint32(decrypted[56:60])
	if tag != 0xdddddddd {
		return nil, errBadObfTag
	}

	var reversed [initHeaderSize]byte
	for i := 0; i < initHeaderSize; i++ {
		reversed[i] = wireHeader[initHeaderSize-1-i]
	}
	encKey, encIV := deriveKey(reversed[:], secret)
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	encStream := cipher.NewCTR(encBlock, encIV)

	return &obfConn{
		Conn: rawConn,
		enc:  encStream,
		dec:  decStream,
	}, nil
}
