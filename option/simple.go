package option

import (
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
)

type SocksInboundOptions struct {
	ListenOptions
	Users          []auth.User           `json:"users,omitempty"`
	DomainResolver *DomainResolveOptions `json:"domain_resolver,omitempty"`
}

type HTTPMixedInboundOptions struct {
	ListenOptions
	Users          []auth.User           `json:"users,omitempty"`
	DomainResolver *DomainResolveOptions `json:"domain_resolver,omitempty"`
	SetSystemProxy bool                  `json:"set_system_proxy,omitempty"`
	// InHive fork: per-process proxy-auth bypass (Happ-style). Connections from a
	// whitelisted process (exe basename on desktop, android package on Android)
	// skip auth so browsers via the system proxy don't get a 407 login dialog,
	// while other local apps still get challenged. MUST stay a KNOWN field here —
	// the upstream strict JSON decoder (DisallowUnknownFields, option/options.go)
	// rejects the whole config if this key is sent but undefined (the 2026-05-23
	// regression that crashed Android). On future sing-box merges, re-verify this
	// field survives. See feedback_security_localhost_auth.md + feedback_build_singbox_merge.md.
	ProcessWhitelist []string `json:"process_whitelist,omitempty"`
	InboundTLSOptionsContainer
}

type SOCKSOutboundOptions struct {
	DialerOptions
	ServerOptions
	Version    string             `json:"version,omitempty"`
	Username   string             `json:"username,omitempty"`
	Password   string             `json:"password,omitempty"`
	Network    NetworkList        `json:"network,omitempty"`
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
}

type HTTPOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	OutboundTLSOptionsContainer
	Path    string               `json:"path,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
}
