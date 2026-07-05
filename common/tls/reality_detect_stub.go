//go:build !with_utls

package tls

// IsRealityClientConfig always reports false in builds without uTLS: REALITY
// requires uTLS, so no REALITY client config can exist here.
func IsRealityClientConfig(config Config) bool {
	return false
}
