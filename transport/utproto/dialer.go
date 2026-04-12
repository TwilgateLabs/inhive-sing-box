package utproto

import (
	"context"
	"net"
	"time"
)

// Dial performs the full UTProto client handshake over an already-dialed
// TCP connection `rawConn` and returns a net.Conn whose Read/Write carry
// arbitrary application data through the UTProto transport stack.
//
// The returned conn does NOT speak MTProto protocol; the obfuscated2
// layer is a transparent byte stream and accepts any payload.
//
// Handshake flow:
//
//  1. Build FakeTLS ClientHello (chromeProfile + HMAC digest + timestamp)
//  2. Write ClientHello to rawConn
//  3. Read ServerHello + CCS + AppData; verify HMAC digest from server
//  4. Send client ChangeCipherSpec (\x14\x03\x03\x00\x01\x01)
//  5. Wrap rawConn with fakeTLSConn (TLS record framer)
//  6. Generate obfuscated2 init header, write it in plaintext through
//     fakeTLSConn (server reads it unwrapped from TLS records)
//  7. Wrap fakeTLSConn with obfConn (AES-256-CTR streaming)
//  8. Return obfConn — the user's application data flows through it
func Dial(ctx context.Context, rawConn net.Conn, cfg *Config) (net.Conn, error) {
	// Apply ctx deadline to the underlying conn if set.
	if dl, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(dl)
		defer rawConn.SetDeadline(time.Time{})
	}

	unixTime := int32(time.Now().Unix())

	// 1. Build ClientHello
	hello, helloRand, err := generateClientHello(cfg, unixTime)
	if err != nil {
		return nil, err
	}

	// 2. Write ClientHello
	if _, err := rawConn.Write(hello); err != nil {
		return nil, err
	}

	// 3. Read + validate ServerHello response
	if _, err := validateServerHello(rawConn, cfg.Secret, helloRand); err != nil {
		return nil, err
	}

	// 4. Send client ChangeCipherSpec
	if _, err := rawConn.Write([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}); err != nil {
		return nil, err
	}

	// 5. Wrap with FakeTLS record framer
	framer := newFakeTLSConn(rawConn)

	// 6. Generate obfuscated2 init header (dcID=1 matches mtprotoproxy default)
	initHeader, err := genInitHeader(1)
	if err != nil {
		return nil, err
	}

	// 7. Setup obfuscated2 — returns wire-ready header (bytes [56:] encrypted)
	//    and an obfConn with enc counter already at position 64.
	conn, wireHeader, err := newObfConn(framer, initHeader, cfg.Secret)
	if err != nil {
		return nil, err
	}

	// 8. Write the wire-ready init header through FakeTLS framer
	if _, err := framer.Write(wireHeader[:]); err != nil {
		return nil, err
	}

	return conn, nil
}
