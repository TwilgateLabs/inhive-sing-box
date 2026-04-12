// Package utproto implements the UTProto transport — a fork of Telegram's
// MTProto FakeTLS transport layer, generalized for arbitrary payloads.
//
// This package has zero sing-box dependencies (stdlib + golang.org/x/crypto
// only) so it can be copy-pasted into Xray-core, Mihomo, v2ray-core or any
// other Go-based proxy core with only a thin adapter on top.
//
// Protocol stack (bottom-up):
//
//	[raw TCP socket]
//	  ↓
//	[FakeTLS framing]    TLS record header \x17\x03\x03 + length
//	  ↓
//	[obfuscated2]        AES-256-CTR keyed from 64-byte init header
//	  ↓
//	[payload]            arbitrary bytes (VPN data, not MTProto)
//
// Ported from tdlib/td/mtproto/TlsInit.cpp and TcpTransport.cpp
// (https://github.com/tdlib/td, BSL-1.0).
package utproto

// Config is the connection-level configuration for a UTProto client.
type Config struct {
	// Secret is the 16-byte shared secret (hex-decoded).
	// On the wire this is prefixed with 0xee to signal FakeTLS mode.
	Secret [16]byte

	// TLSDomain is the SNI/fronting domain the server claims to be.
	// Must match the domain the server was configured with.
	// Example: "learn.microsoft.com".
	TLSDomain string
}
