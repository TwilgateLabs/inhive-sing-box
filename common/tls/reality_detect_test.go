//go:build with_utls

package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// newTestRealityClient builds a real REALITY client config from valid options
// (32-byte public key, 8-byte short id) so the detector is tested against the
// genuine concrete type, not a mock.
func newTestRealityClient(t *testing.T) Config {
	t.Helper()
	cfg, err := NewRealityClient(context.Background(), logger.NOP(), "google.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "google.com",
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			ShortID:   "0123456789abcdef",
			PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
		},
		UTLS: &option.OutboundUTLSOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("build reality client: %v", err)
	}
	return cfg
}

func TestIsRealityClientConfig(t *testing.T) {
	// A genuine REALITY client config → true.
	if !IsRealityClientConfig(newTestRealityClient(t)) {
		t.Fatalf("reality client config not detected")
	}
	// nil → false, never panic.
	if IsRealityClientConfig(nil) {
		t.Fatalf("nil config must not be classified as reality")
	}
	// A plain (non-reality) uTLS client config → false.
	stdCfg, err := NewUTLSClient(context.Background(), logger.NOP(), "google.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "google.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("build utls client: %v", err)
	}
	if IsRealityClientConfig(stdCfg) {
		t.Fatalf("plain uTLS config must not be classified as reality")
	}
}
