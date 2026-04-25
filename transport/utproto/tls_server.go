package utproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// Time skew tolerated when validating the client's XOR'd timestamp.
// Values match the existing client-side test (integration_test.go
// TestHMACServerVerification) and mtprotoproxy's defaults.
const (
	maxSkewFuture      = int64(20 * 60) // client may be up to 20min ahead of server clock
	maxSkewPast        = int64(10 * 60) // client may be up to 10min behind server clock
	clientHelloMinSize = 517            // tdlib pads to ≥517 bytes via opPadding
	clientHelloMaxSize = 16384          // TLS record max payload
)

// readClientHello reads one TLS record and returns the full buffer
// (header + body). Even on error the returned slice contains any bytes
// already consumed — callers replay them when proxying to a fallback
// origin.
func readClientHello(conn net.Conn) ([]byte, error) {
	var buf bytes.Buffer

	hdr := make([]byte, 5)
	n, err := io.ReadFull(conn, hdr)
	buf.Write(hdr[:n])
	if err != nil {
		return buf.Bytes(), err
	}

	if hdr[0] != 0x16 || hdr[1] != 0x03 || hdr[2] != 0x01 {
		return buf.Bytes(), errBadClientHello
	}

	recordLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recordLen+5 < clientHelloMinSize {
		return buf.Bytes(), errClientHelloTooSmall
	}
	if recordLen > clientHelloMaxSize {
		return buf.Bytes(), errClientHelloTooLarge
	}

	body := make([]byte, recordLen)
	n, err = io.ReadFull(conn, body)
	buf.Write(body[:n])
	if err != nil {
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}

// identifyUser tries each user's secret against the ClientHello HMAC.
// Returns the matched user and the 32-byte client_rand (buf[11:43] —
// used later as seed in ServerHello MAC computation). Uses constant-
// time compare on the first 28 bytes (last 4 are XOR'd with timestamp).
func identifyUser(clientHello []byte, users []ServerUser) (*ServerUser, []byte, error) {
	if len(clientHello) < 43 {
		return nil, nil, errClientHelloTooSmall
	}

	received := make([]byte, 32)
	copy(received, clientHello[11:43])

	msg := make([]byte, len(clientHello))
	copy(msg, clientHello)
	for i := 11; i < 43; i++ {
		msg[i] = 0
	}

	now := time.Now().Unix()

	for i := range users {
		mac := hmac.New(sha256.New, users[i].Secret[:])
		mac.Write(msg)
		computed := mac.Sum(nil)

		if subtle.ConstantTimeCompare(computed[:28], received[:28]) != 1 {
			continue
		}

		var xorBytes [4]byte
		for j := 0; j < 4; j++ {
			xorBytes[j] = received[28+j] ^ computed[28+j]
		}
		unixTime := int64(int32(binary.LittleEndian.Uint32(xorBytes[:])))

		skew := now - unixTime
		if skew < -maxSkewFuture || skew > maxSkewPast {
			return nil, nil, errTimeSkew
		}

		return &users[i], received, nil
	}

	return nil, nil, errNoMatchingUser
}

// writeServerHello builds the 3-record server response and writes it
// to conn in a single Write call so it lands as one TCP send.
//
// Byte layout (138 + N total, N = padLen ∈ [32..287]):
//
//	[0:3]     \x16\x03\x03                TLS record type+version
//	[3:5]     u16 = 122                   record 1 length
//	[5]       \x02                        handshake_type: server_hello
//	[6:9]     0x00 0x00 0x76              uint24 handshake_len = 118
//	[9:11]    \x03\x03                    legacy_version TLS 1.2
//	[11:43]   server_random (DIGEST)      HMAC slot
//	[43]      \x20                        session_id_len = 32
//	[44:76]   <sessionID echo>
//	[76:78]   \x13\x01                    cipher_suite TLS_AES_128_GCM_SHA256
//	[78]      \x00                        compression_method null
//	[79:81]   \x00\x2e                    extensions_length = 46
//	[81:87]   \x00\x2b\x00\x02\x03\x04    supported_versions ext (TLS 1.3)
//	[87:127]  key_share ext               x25519 group + 32B fake pubkey
//	[127:133] \x14\x03\x03\x00\x01\x01    ChangeCipherSpec record
//	[133:136] \x17\x03\x03                AppData record header
//	[136:138] u16 = padLen                AppData length
//	[138:]    <random padding>
//
// Client validateServerHello validates HMAC over the whole buffer with
// bytes [11:43] zeroed, seeded by its own helloRand. Server computes
// HMAC(secret, client_rand || buf_with_digest_zeroed) and writes
// result at [11:43].
func writeServerHello(conn net.Conn, secret [16]byte, clientRand []byte, sessionID []byte) error {
	if len(clientRand) != 32 || len(sessionID) != 32 {
		return errBadBufferSize
	}

	var x25519pub [32]byte
	if _, err := io.ReadFull(rand.Reader, x25519pub[:]); err != nil {
		return err
	}

	var lenRand [1]byte
	if _, err := io.ReadFull(rand.Reader, lenRand[:]); err != nil {
		return err
	}
	padLen := 32 + int(lenRand[0])
	padding := make([]byte, padLen)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return err
	}

	// Record 1 body (122 bytes). Indices relative to record 1 body;
	// overall buffer offset = index + 5 (skipping record header).
	body := make([]byte, 122)
	body[0] = 0x02
	body[1] = 0x00
	body[2] = 0x00
	body[3] = 0x76 // handshake_len = 118
	body[4] = 0x03
	body[5] = 0x03
	// body[6:38] digest slot — zero, filled after HMAC
	body[38] = 0x20
	copy(body[39:71], sessionID)
	body[71] = 0x13
	body[72] = 0x01
	body[73] = 0x00
	body[74] = 0x00
	body[75] = 0x2e // extensions_length = 46
	body[76] = 0x00
	body[77] = 0x2b
	body[78] = 0x00
	body[79] = 0x02
	body[80] = 0x03
	body[81] = 0x04
	body[82] = 0x00
	body[83] = 0x33
	body[84] = 0x00
	body[85] = 0x24
	body[86] = 0x00
	body[87] = 0x1d
	body[88] = 0x00
	body[89] = 0x20
	copy(body[90:122], x25519pub[:])

	rec1 := make([]byte, 5+122)
	rec1[0] = 0x16
	rec1[1] = 0x03
	rec1[2] = 0x03
	binary.BigEndian.PutUint16(rec1[3:5], 122)
	copy(rec1[5:], body)

	rec2 := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

	rec3 := make([]byte, 5+len(padding))
	rec3[0] = 0x17
	rec3[1] = 0x03
	rec3[2] = 0x03
	binary.BigEndian.PutUint16(rec3[3:5], uint16(len(padding)))
	copy(rec3[5:], padding)

	buf := make([]byte, 0, len(rec1)+len(rec2)+len(rec3))
	buf = append(buf, rec1...)
	buf = append(buf, rec2...)
	buf = append(buf, rec3...)

	mac := hmac.New(sha256.New, secret[:])
	mac.Write(clientRand)
	mac.Write(buf)
	digest := mac.Sum(nil)
	copy(buf[11:43], digest)

	_, err := conn.Write(buf)
	return err
}
