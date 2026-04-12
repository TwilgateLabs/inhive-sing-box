package option

type UTProtoOutboundOptions struct {
	DialerOptions
	ServerOptions
	Secret    string      `json:"secret"`
	TLSDomain string      `json:"tls_domain"`
	Network   NetworkList `json:"network,omitempty"`
}
