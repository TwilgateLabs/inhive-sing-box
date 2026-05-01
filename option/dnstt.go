package option

// DnsttOutboundOptions — DNSTT (DNS tunneling) outbound.
// DNSTT tunnels TCP through DNS queries (TXT/CNAME records).
// Useful in restricted networks where only DNS traffic is allowed.
//
// Server setup: https://www.bamsoftware.com/software/dnstt/
// Params:
//   domain   — NS delegation zone, e.g. "t.example.com"
//   pubkey   — server Ed25519 public key (hex, 32 bytes = 64 hex chars)
//   resolver — DNS resolver to use for tunneling:
//              UDP:  "8.8.8.8:53"  (default port 53 if omitted)
//              DoH:  "https://dns.google/dns-query"
//              DoT:  "tls://1.1.1.1"
type DnsttOutboundOptions struct {
	DialerOptions
	Domain   string `json:"domain"`
	Pubkey   string `json:"pubkey"`
	Resolver string `json:"resolver,omitempty"` // default "8.8.8.8:53"
}
