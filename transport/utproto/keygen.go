package utproto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
)

// GenCurve25519PublicKey generates a random Curve25519 private key and
// returns its 32-byte public key encoding. Used to fill the `key_share`
// TLS extension inside the FakeTLS ClientHello.
//
// The tdlib reference implementation rolls its own x25519 point generation
// via BigNum + quadratic residues (see TlsInit.cpp Op::key); we use the
// stdlib `crypto/ecdh` Curve25519 which produces the same wire-compatible
// public keys without re-implementing modular arithmetic.
func GenCurve25519PublicKey() ([32]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return [32]byte{}, err
	}
	pub := priv.PublicKey().Bytes()
	var out [32]byte
	copy(out[:], pub)
	return out, nil
}

// GenFakeMLKem768Key writes 1184 bytes of ML-KEM-768 public-key-shaped
// random data into dst. It is NOT a real ML-KEM key — it is a noise pattern
// whose byte statistics match a valid ML-KEM-768 encapsulation key so DPI
// cannot distinguish ClientHellos with real vs decoy post-quantum shares.
//
// Ported from tdlib TlsInit.cpp Op::MlKem768Key:
//
//	for i in 0..384:
//	  a, b := rand() % 3329, rand() % 3329
//	  dst[0] = a & 0xff
//	  dst[1] = (a >> 8) | ((b & 0x0f) << 4)
//	  dst[2] = b >> 4
//	  dst += 3
//	// followed by 32 random bytes
//
// dst must be exactly 1184 bytes long (384*3 + 32).
func GenFakeMLKem768Key(dst []byte) error {
	const size = 384*3 + 32
	if len(dst) != size {
		return errBadBufferSize
	}
	for i := 0; i < 384; i++ {
		a, err := randUint32Mod(3329)
		if err != nil {
			return err
		}
		b, err := randUint32Mod(3329)
		if err != nil {
			return err
		}
		dst[0] = byte(a & 0xff)
		dst[1] = byte((a >> 8) | ((b & 0x0f) << 4))
		dst[2] = byte(b >> 4)
		dst = dst[3:]
	}
	_, err := io.ReadFull(rand.Reader, dst[:32])
	return err
}

// randUint32Mod returns a uniformly-random uint32 in [0, mod) without
// modulo bias, matching tdlib's `Random::secure_uint32() % mod` closely
// enough for the anti-DPI use case (bias at mod=3329 is <10^-7).
func randUint32Mod(mod uint32) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]) % mod, nil
}
