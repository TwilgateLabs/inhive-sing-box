package utproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
)

// obfuscated2 is the inner layer of the UTProto transport. It wraps a
// net.Conn with a symmetric AES-256-CTR stream keyed from a 64-byte init
// header that is sent in-band at the start of the connection.
//
// Ported from tdlib/td/mtproto/TcpTransport.cpp, class ObfuscatedTransport.
//
// Wire format of the 64-byte init header (unencrypted):
//
//	bytes  0..55  : random (with constraints — see genInitHeader)
//	bytes 56..59  : protocol tag (0xdddddddd for intermediate, 0xeeeeeeee for padded)
//	bytes 60..61  : dc_id (little-endian int16)
//	bytes 62..63  : random
//
// Key / IV derivation:
//
//	enc_key = sha256(init[8:40] || secret[:16])
//	enc_iv  = init[40:56]
//	reversed = reverse(init[:64])
//	dec_key = sha256(reversed[8:40] || secret[:16])
//	dec_iv  = reversed[40:56]
//
// Everything after the init header is AES-256-CTR encrypted; the init
// header itself is written in the clear (inside a FakeTLS application
// record when running in FakeTLS mode).

const initHeaderSize = 64

// obfConn is a net.Conn that transparently XORs through AES-256-CTR
// streams in both directions.
type obfConn struct {
	net.Conn
	enc cipher.Stream
	dec cipher.Stream
}

func (c *obfConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.dec.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (c *obfConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	c.enc.XORKeyStream(buf, p)
	return c.Conn.Write(buf)
}

// newObfConn sets up obfuscated2 over rawConn. It returns a wrapped
// net.Conn plus the wire-ready 64-byte init header that the caller must
// write to rawConn BEFORE using the returned conn.
//
// The wire-ready header has bytes [0:56] in plaintext (so the server can
// derive the same AES key) and bytes [56:64] encrypted through the
// enc cipher. This matches mtprotoproxy's expectation: it decrypts the
// full 64 bytes with the same cipher and checks proto_tag at [56:60].
//
// Crucially, the enc cipher has already processed 64 bytes of
// keystream (the init header), so its CTR counter is at position 64 —
// exactly where the server's decryptor will be after
// decryptor.decrypt(handshake). The dec cipher starts at counter 0
// because the server's encryptor hasn't processed any header bytes.
func newObfConn(rawConn net.Conn, initHeader [initHeaderSize]byte, secret [16]byte) (*obfConn, [initHeaderSize]byte, error) {
	// --- encrypt direction (client → server) ---
	encKey, encIV := deriveKey(initHeader[:], secret)
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, [initHeaderSize]byte{}, err
	}
	encStream := cipher.NewCTR(encBlock, encIV)

	// Encrypt full header through the enc stream to advance CTR to pos 64.
	var wireHeader [initHeaderSize]byte
	encStream.XORKeyStream(wireHeader[:], initHeader[:])
	// Keep bytes [0:56] in plaintext — only [56:64] stays encrypted.
	copy(wireHeader[:56], initHeader[:56])

	// --- decrypt direction (server → client) ---
	var reversed [initHeaderSize]byte
	for i := 0; i < initHeaderSize; i++ {
		reversed[i] = initHeader[initHeaderSize-1-i]
	}
	decKey, decIV := deriveKey(reversed[:], secret)
	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, [initHeaderSize]byte{}, err
	}
	decStream := cipher.NewCTR(decBlock, decIV)

	return &obfConn{
		Conn: rawConn,
		enc:  encStream, // counter at 64 — synced with server's decryptor
		dec:  decStream,  // counter at 0  — synced with server's encryptor
	}, wireHeader, nil
}

// deriveKey extracts (aes_key, aes_iv) for one direction from a 64-byte
// header and the 16-byte shared secret.
func deriveKey(header []byte, secret [16]byte) ([]byte, []byte) {
	keyMaterial := make([]byte, 32+16)
	copy(keyMaterial[:32], header[8:40])
	copy(keyMaterial[32:], secret[:])
	sum := sha256.Sum256(keyMaterial)

	iv := make([]byte, 16)
	copy(iv, header[40:56])
	return sum[:], iv
}

// genInitHeader returns a valid random 64-byte obfuscated2 init header
// with protocol tag set to intermediate framing (0xdddddddd) and dcID=1.
//
// Validity constraints (from tdlib TcpTransport.cpp):
//
//	header[0]           != 0xef      (excludes old MTProto abridged)
//	header[0..4] as u32 not in { 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xdddddddd, 0xeeeeeeee }
//	header[4..8] as u32 != 0
//
// We retry until we roll a header satisfying them.
func genInitHeader(dcID int16) ([initHeaderSize]byte, error) {
	var h [initHeaderSize]byte
	for {
		if _, err := io.ReadFull(rand.Reader, h[:]); err != nil {
			return h, err
		}
		if h[0] == 0xef {
			continue
		}
		first := uint32(h[0]) | uint32(h[1])<<8 | uint32(h[2])<<16 | uint32(h[3])<<24
		if first == 0x44414548 || first == 0x54534f50 || first == 0x20544547 ||
			first == 0x4954504f || first == 0xdddddddd || first == 0xeeeeeeee {
			continue
		}
		second := uint32(h[4]) | uint32(h[5])<<8 | uint32(h[6])<<16 | uint32(h[7])<<24
		if second == 0 {
			continue
		}
		break
	}
	// intermediate protocol tag
	h[56], h[57], h[58], h[59] = 0xdd, 0xdd, 0xdd, 0xdd
	// dc_id little-endian
	h[60] = byte(dcID)
	h[61] = byte(dcID >> 8)
	return h, nil
}
