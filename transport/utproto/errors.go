package utproto

import "errors"

var (
	errBadBufferSize       = errors.New("utproto: bad buffer size")
	errHandshakeNotImpl    = errors.New("utproto: FakeTLS handshake not implemented yet")
	errHandshakeTooShort   = errors.New("utproto: server response too short")
	errHandshakeBadDigest  = errors.New("utproto: server handshake digest mismatch")
	errBadClientHello      = errors.New("utproto: bad client hello")
	errClientHelloTooSmall = errors.New("utproto: client hello too small")
	errClientHelloTooLarge = errors.New("utproto: client hello exceeds 16KB")
	errNoMatchingUser      = errors.New("utproto: no user secret matches client hmac")
	errTimeSkew            = errors.New("utproto: client timestamp skew too large")
	errBadObfTag           = errors.New("utproto: bad obf2 protocol tag (wrong secret?)")
)
