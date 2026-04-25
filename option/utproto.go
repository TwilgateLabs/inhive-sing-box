package option

type UTProtoOutboundOptions struct {
	DialerOptions
	ServerOptions
	Secret    string      `json:"secret"`
	TLSDomain string      `json:"tls_domain"`
	Network   NetworkList `json:"network,omitempty"`
}

// UTProtoInboundOptions configures the native sing-box UTProto server.
// Inner framing after FakeTLS+obf2 is VLESS (backward-compat with
// existing clients whose subscription URLs include vless_uuid), so each
// user carries both a 16-byte UTProto secret and a VLESS UUID. Dual
// auth means an attacker must compromise both to impersonate a user.
type UTProtoInboundOptions struct {
	ListenOptions
	// TLSDomain is informational on the server — the FakeTLS handshake
	// only uses the per-user secret for HMAC, not the domain. Kept for
	// parity with outbound options and future SNI-based fallback.
	TLSDomain string              `json:"tls_domain,omitempty"`
	Users     []UTProtoInboundUser `json:"users"`
	// Fallback configures a destination for TLS traffic that fails
	// UTProto authentication (wrong/missing secret, malformed
	// ClientHello). When set, the raw bytes consumed from the client
	// are replayed to the fallback and piped bidirectionally — a
	// passive DPI scanner sees a complete TLS handshake to a
	// legitimate origin instead of a closed connection. Recommended:
	// learn.microsoft.com:443.
	Fallback *UTProtoFallback `json:"fallback,omitempty"`
}

type UTProtoInboundUser struct {
	Name      string `json:"name"`
	Secret    string `json:"secret"`     // 32 hex chars (16 bytes)
	VLESSUUID string `json:"vless_uuid"` // UUID string, e.g. "761bb14f-51aa-49b6-b583-37ea11132568"
}

type UTProtoFallback struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}
