package utproto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
)

// FakeTLS ClientHello generator.
//
// Ported from tdlib/td/mtproto/TlsInit.cpp (BSL-1.0). The approach is a
// declarative DSL: ClientHello is described as a sequence of Ops, then
// rendered in two passes — pass 1 (calcLength) computes the total size,
// pass 2 (store) actually writes bytes with begin/end scope filling in
// 2-byte uint16 length placeholders.
//
// The reference profile below is the non-Darwin (Chrome-on-Linux) Browser
// Profile from tdlib as of 2026-03; it uses ECH extension 0xfe0d and a
// randomized extension permutation via Op::Permutation.

// ----------------------------------------------------------------------
// Op types
// ----------------------------------------------------------------------

type opKind int

const (
	opString opKind = iota
	opRandom
	opZero
	opDomain
	opGrease
	opKey
	opMlKem768Key
	opBeginScope
	opEndScope
	opPermutation
	opRandomValue
	opPadding
)

type op struct {
	kind     opKind
	length   int
	seed     int
	data     string
	parts    [][]op // for permutation and random_value
	valueIdx int    // for random_value: which part was chosen
}

func opStr(s string) op             { return op{kind: opString, data: s} }
func opRand(n int) op               { return op{kind: opRandom, length: n} }
func opZeroN(n int) op              { return op{kind: opZero, length: n} }
func opDom() op                     { return op{kind: opDomain} }
func opGr(seed int) op              { return op{kind: opGrease, seed: seed} }
func opKeyShare() op                { return op{kind: opKey} }
func opMlKem() op                   { return op{kind: opMlKem768Key} }
func opBeg() op                     { return op{kind: opBeginScope} }
func opEnd() op                     { return op{kind: opEndScope} }
func opPad() op                     { return op{kind: opPadding} }
func opPerm(parts [][]op) op        { return op{kind: opPermutation, parts: parts} }
// opRandVal picks a random sub-sequence from parts. An empty parts slice is
// a programming error in the profile definition; we emit a sentinel op with
// valueIdx = -1 so the two-pass renderer returns an error instead of panicking
// inside a connection handler.
func opRandVal(parts [][]op) op {
	if len(parts) == 0 {
		return op{kind: opRandomValue, parts: nil, valueIdx: -1}
	}
	return op{kind: opRandomValue, parts: parts, valueIdx: mrand.IntN(len(parts))}
}

// opEchPayload generates a random-length payload (144/176/208/240 bytes)
// mimicking ECH encrypted payload size distribution.
func opEchPayload() op {
	return op{kind: opRandom, length: mrand.IntN(4)*32 + 144}
}

// ----------------------------------------------------------------------
// Browser profile — non-Darwin (Chrome-on-Linux), 2026-03 snapshot
// Transcribed from tdlib/td/mtproto/TlsInit.cpp get_default() #else branch.
// ----------------------------------------------------------------------

func chromeProfile() []op {
	return []op{
		opStr("\x16\x03\x01"),
		opBeg(),
		opStr("\x01\x00"),
		opBeg(),
		opStr("\x03\x03"),
		opZeroN(32),
		opStr("\x20"),
		opRand(32),
		opStr("\x00\x20"),
		opGr(0),
		opStr("\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"),
		opBeg(),
		opGr(2),
		opStr("\x00\x00"),
		opPerm([][]op{
			{opStr("\x00\x00"), opBeg(), opBeg(), opStr("\x00"), opBeg(), opDom(), opEnd(), opEnd(), opEnd()},
			{opStr("\x00\x05\x00\x05\x01\x00\x00\x00\x00")},
			{opStr("\x00\x0a\x00\x0c\x00\x0a"), opGr(4), opStr("\x11\xec\x00\x1d\x00\x17\x00\x18")},
			{opStr("\x00\x0b\x00\x02\x01\x00")},
			{opStr("\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01")},
			{opStr("\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31")},
			{opStr("\x00\x12\x00\x00")},
			{opStr("\x00\x17\x00\x00")},
			{opStr("\x00\x1b\x00\x03\x02\x00\x02")},
			{opStr("\x00\x23\x00\x00")},
			{opStr("\x00\x2b\x00\x07\x06"), opGr(6), opStr("\x03\x04\x03\x03")},
			{opStr("\x00\x2d\x00\x02\x01\x01")},
			{opStr("\x00\x33\x04\xef\x04\xed"), opGr(4), opStr("\x00\x01\x00\x11\xec\x04\xc0"), opMlKem(), opKeyShare(), opStr("\x00\x1d\x00\x20"), opKeyShare()},
			{opStr("\x44\xcd\x00\x05\x00\x03\x02\x68\x32")},
			{opStr("\xfe\x0d"), opBeg(), opStr("\x00\x00\x01\x00\x01"), opRand(1), opStr("\x00\x20"), opRand(32), opBeg(), opEchPayload(), opEnd(), opEnd()},
			{opStr("\xff\x01\x00\x01\x00")},
		}),
		opGr(3),
		opStr("\x00\x01\x00"),
		opPad(),
		opEnd(),
		opEnd(),
		opEnd(),
	}
}

// ----------------------------------------------------------------------
// GREASE
// ----------------------------------------------------------------------

const greaseSize = 7

// genGrease fills out with 7 GREASE bytes following Chrome's rules:
// each byte is of the form 0x?A where ? is random, and adjacent bytes
// must differ (flip low nibble's 0x10 bit if they collide).
func genGrease() ([greaseSize]byte, error) {
	var g [greaseSize]byte
	if _, err := io.ReadFull(rand.Reader, g[:]); err != nil {
		return g, err
	}
	for i := 0; i < greaseSize; i++ {
		g[i] = (g[i] & 0xf0) + 0x0a
	}
	for i := 1; i < greaseSize; i += 2 {
		if g[i] == g[i-1] {
			g[i] ^= 0x10
		}
	}
	return g, nil
}

// ----------------------------------------------------------------------
// Two-pass render
// ----------------------------------------------------------------------

type ctxData struct {
	grease [greaseSize]byte
	domain string
}

// calcLength runs pass 1 and returns the total rendered length in bytes.
func calcLength(ops []op, c *ctxData) (int, error) {
	var size int
	var scopeStack []int
	var walk func(ops []op) error
	walk = func(ops []op) error {
		for _, o := range ops {
			switch o.kind {
			case opString:
				size += len(o.data)
			case opRandom:
				if o.length <= 0 || o.length > 2048 {
					return errors.New("utproto: invalid random length")
				}
				size += o.length
			case opZero:
				if o.length <= 0 || o.length > 2048 {
					return errors.New("utproto: invalid zero length")
				}
				size += o.length
			case opDomain:
				size += len(c.domain)
			case opGrease:
				if o.seed < 0 || o.seed >= greaseSize {
					return errors.New("utproto: invalid grease seed")
				}
				size += 2
			case opKey:
				size += 32
			case opMlKem768Key:
				size += 1184
			case opBeginScope:
				size += 2
				scopeStack = append(scopeStack, size)
			case opEndScope:
				if len(scopeStack) == 0 {
					return errors.New("utproto: unbalanced scopes")
				}
				begin := scopeStack[len(scopeStack)-1]
				scopeStack = scopeStack[:len(scopeStack)-1]
				if size-begin >= 1<<14 {
					return errors.New("utproto: scope too big")
				}
			case opPermutation:
				for _, part := range o.parts {
					if err := walk(part); err != nil {
						return err
					}
				}
			case opRandomValue:
				if len(o.parts) == 0 || o.valueIdx < 0 || o.valueIdx >= len(o.parts) {
					return errors.New("utproto: random_value with invalid parts")
				}
				if err := walk(o.parts[o.valueIdx]); err != nil {
					return err
				}
			case opPadding:
				if size < 513 {
					size = 517
				}
			}
		}
		return nil
	}
	if err := walk(ops); err != nil {
		return 0, err
	}
	if len(scopeStack) != 0 {
		return 0, errors.New("utproto: unbalanced scopes")
	}
	return size, nil
}

// store runs pass 2: writes bytes into dst (exact-size buffer pre-allocated
// to calcLength's result).
func store(dst []byte, ops []op, c *ctxData) error {
	pos := 0
	var scopeStack []int

	var walk func(ops []op) error
	walk = func(ops []op) error {
		for _, o := range ops {
			switch o.kind {
			case opString:
				copy(dst[pos:], o.data)
				pos += len(o.data)
			case opRandom:
				if _, err := io.ReadFull(rand.Reader, dst[pos:pos+o.length]); err != nil {
					return err
				}
				pos += o.length
			case opZero:
				for i := 0; i < o.length; i++ {
					dst[pos+i] = 0
				}
				pos += o.length
			case opDomain:
				copy(dst[pos:], c.domain)
				pos += len(c.domain)
			case opGrease:
				dst[pos] = c.grease[o.seed]
				dst[pos+1] = c.grease[o.seed]
				pos += 2
			case opKey:
				k, err := GenCurve25519PublicKey()
				if err != nil {
					return err
				}
				copy(dst[pos:], k[:])
				pos += 32
			case opMlKem768Key:
				if err := GenFakeMLKem768Key(dst[pos : pos+1184]); err != nil {
					return err
				}
				pos += 1184
			case opBeginScope:
				scopeStack = append(scopeStack, pos)
				pos += 2
			case opEndScope:
				begin := scopeStack[len(scopeStack)-1]
				scopeStack = scopeStack[:len(scopeStack)-1]
				payload := pos - begin - 2
				dst[begin] = byte(payload >> 8)
				dst[begin+1] = byte(payload)
			case opPermutation:
				// Render each part into its own slice, then shuffle and concat.
				renderedParts := make([][]byte, len(o.parts))
				for i, part := range o.parts {
					partLen, err := calcLength(part, c)
					if err != nil {
						return err
					}
					buf := make([]byte, partLen)
					if err := store(buf, part, c); err != nil {
						return err
					}
					renderedParts[i] = buf
				}
				mrand.Shuffle(len(renderedParts), func(i, j int) {
					renderedParts[i], renderedParts[j] = renderedParts[j], renderedParts[i]
				})
				for _, p := range renderedParts {
					copy(dst[pos:], p)
					pos += len(p)
				}
			case opRandomValue:
				if len(o.parts) == 0 || o.valueIdx < 0 || o.valueIdx >= len(o.parts) {
					return errors.New("utproto: random_value with invalid parts")
				}
				if err := walk(o.parts[o.valueIdx]); err != nil {
					return err
				}
			case opPadding:
				need := 513 - pos
				if need > 0 {
					padOps := []op{
						opStr("\x00\x15"),
						opBeg(),
						opZeroN(need),
						opEnd(),
					}
					if err := walk(padOps); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	return walk(ops)
}

// ----------------------------------------------------------------------
// generateClientHello — top-level entry used by dialer
// ----------------------------------------------------------------------

// generateClientHello builds the FakeTLS ClientHello record, computes the
// HMAC-SHA256 digest over it (with the digest slot zeroed), XORs the
// last 4 bytes of the digest with the unix timestamp, and returns the
// finished bytes plus the 32-byte digest (aka hello_rand — used later
// to authenticate the server response).
func generateClientHello(cfg *Config, unixTime int32) (hello []byte, helloRand [32]byte, err error) {
	grease, err := genGrease()
	if err != nil {
		return nil, [32]byte{}, err
	}
	c := &ctxData{grease: grease, domain: cfg.TLSDomain}

	ops := chromeProfile()
	length, err := calcLength(ops, c)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if length < 11+32 {
		return nil, [32]byte{}, errors.New("utproto: render too small for hash")
	}
	hello = make([]byte, length)
	if err := store(hello, ops, c); err != nil {
		return nil, [32]byte{}, err
	}

	// Clear digest slot [11..43] — it was zeroed by opZeroN(32) already,
	// but we re-zero defensively in case the slot moved.
	for i := 11; i < 11+32; i++ {
		hello[i] = 0
	}

	// HMAC-SHA256(secret, hello) → digest; write into [11..43]
	mac := hmac.New(sha256.New, cfg.Secret[:])
	mac.Write(hello)
	digest := mac.Sum(nil)
	copy(hello[11:11+32], digest)

	// XOR last 4 bytes of digest with unix time (little-endian int32)
	old := int32(binary.LittleEndian.Uint32(hello[11+28 : 11+32]))
	binary.LittleEndian.PutUint32(hello[11+28:11+32], uint32(old^unixTime))

	copy(helloRand[:], hello[11:11+32])
	return hello, helloRand, nil
}

// validateServerHello reads TLS records from r matching tdlib's response
// shape and verifies the server's HMAC digest. On success it returns the
// raw bytes that were read (so they can be discarded from the connection
// buffer); the FakeTLS wrapper takes over from there.
//
// Expected response shape:
//
//	\x16\x03\x03 <len:uint16>   <ServerHello bytes>
//	\x14\x03\x03\x00\x01\x01\x17\x03\x03 <len:uint16>  <ChangeCipherSpec+ApplicationData bytes>
//
// Digest is HMAC-SHA256(secret, hello_rand || response_with_zeroed_digest)
// where the digest slot is at offset [11..43] of the whole response.
func validateServerHello(r io.Reader, secret [16]byte, helloRand [32]byte) ([]byte, error) {
	var buf []byte

	readN := func(n int) ([]byte, error) {
		chunk := make([]byte, n)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, err
		}
		buf = append(buf, chunk...)
		return chunk, nil
	}

	for _, prefix := range [][]byte{
		[]byte("\x16\x03\x03"),
		[]byte("\x14\x03\x03\x00\x01\x01\x17\x03\x03"),
	} {
		got, err := readN(len(prefix))
		if err != nil {
			return nil, err
		}
		for i := range prefix {
			if got[i] != prefix[i] {
				return nil, errors.New("utproto: unexpected server response prefix")
			}
		}
		lenBytes, err := readN(2)
		if err != nil {
			return nil, err
		}
		payloadLen := int(lenBytes[0])<<8 | int(lenBytes[1])
		if payloadLen > 1<<14 {
			return nil, errors.New("utproto: server payload too large")
		}
		if _, err := readN(payloadLen); err != nil {
			return nil, err
		}
	}

	if len(buf) < 11+32 {
		return nil, errHandshakeTooShort
	}

	// Extract original digest and zero the slot for HMAC recomputation.
	var respRand [32]byte
	copy(respRand[:], buf[11:11+32])
	for i := 11; i < 11+32; i++ {
		buf[i] = 0
	}

	mac := hmac.New(sha256.New, secret[:])
	mac.Write(helloRand[:])
	mac.Write(buf)
	want := mac.Sum(nil)

	if !hmac.Equal(respRand[:], want) {
		return nil, errHandshakeBadDigest
	}

	// Put the original digest bytes back so caller sees untouched buffer.
	copy(buf[11:11+32], respRand[:])
	return buf, nil
}
