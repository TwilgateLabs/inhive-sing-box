//go:build with_utls

package tls

// IsRealityClientConfig reports whether the given client TLS config drives a
// REALITY handshake. Used by transports (e.g. XHTTP) that must mirror Xray's
// mode:"auto" resolution, where the presence of REALITY selects a different
// dial mode. It unwraps the optional kTLS wrapper (Linux only) so a REALITY
// config wrapped for kernel TLS is still recognised.
func IsRealityClientConfig(config Config) bool {
	for {
		switch c := config.(type) {
		case *RealityClientConfig:
			return true
		case *KTLSClientConfig:
			config = c.Config // unwrap and re-check the inner config
		default:
			return false
		}
	}
}
