package xhttp

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func realityTLS(t *testing.T) tls.Config {
	t.Helper()
	cfg, err := tls.NewRealityClient(context.Background(), logger.NOP(), "google.com", option.OutboundTLSOptions{
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

func plainTLS(t *testing.T) tls.Config {
	t.Helper()
	cfg, err := tls.NewClient(context.Background(), logger.NOP(), "google.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "google.com",
	})
	if err != nil {
		t.Fatalf("build plain tls client: %v", err)
	}
	return cfg
}

// TestResolveXHTTPMode covers every branch of the Xray auto-mode mapping.
func TestResolveXHTTPMode(t *testing.T) {
	download := &option.V2RayXHTTPDownloadOptions{}

	tests := []struct {
		name     string
		mode     string
		tls      tls.Config
		download *option.V2RayXHTTPDownloadOptions
		want     string
	}{
		// auto / empty + reality → stream-one (the bug this fixes: was packet-up).
		{"auto+reality", "auto", realityTLS(t), nil, "stream-one"},
		{"empty+reality", "", realityTLS(t), nil, "stream-one"},
		// auto + reality + downloadSettings → stream-up.
		{"auto+reality+download", "auto", realityTLS(t), download, "stream-up"},
		{"empty+reality+download", "", realityTLS(t), download, "stream-up"},
		// auto / empty WITHOUT reality → packet-up (unchanged from prior fall-through).
		{"auto+plain", "auto", plainTLS(t), nil, "packet-up"},
		{"auto+notls", "auto", nil, nil, "packet-up"},
		{"empty+notls", "", nil, nil, "packet-up"},
		{"auto+plain+download", "auto", plainTLS(t), download, "packet-up"},
		// Explicitly configured modes must pass through untouched, reality or not.
		{"explicit stream-one", "stream-one", realityTLS(t), nil, "stream-one"},
		{"explicit stream-up", "stream-up", realityTLS(t), download, "stream-up"},
		{"explicit packet-up", "packet-up", realityTLS(t), nil, "packet-up"},
		{"explicit stream-down passthrough", "stream-down", nil, nil, "stream-down"},
		// An explicit packet-up on a reality config stays packet-up (no override).
		{"explicit packet-up on reality", "packet-up", realityTLS(t), download, "packet-up"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveXHTTPMode(tc.mode, tc.tls, tc.download)
			if got != tc.want {
				t.Fatalf("resolveXHTTPMode(%q, tls=%v, download=%v) = %q, want %q",
					tc.mode, tc.tls != nil, tc.download != nil, got, tc.want)
			}
		})
	}
}
