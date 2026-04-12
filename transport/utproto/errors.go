package utproto

import "errors"

var (
	errBadBufferSize      = errors.New("utproto: bad buffer size")
	errHandshakeNotImpl   = errors.New("utproto: FakeTLS handshake not implemented yet")
	errHandshakeTooShort  = errors.New("utproto: server response too short")
	errHandshakeBadDigest = errors.New("utproto: server handshake digest mismatch")
)
