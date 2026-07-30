//go:build go1.24

package tls

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// captureLogger records Warn lines so the test can assert on them. Every other
// level is a no-op — we only care that the honest ECH warning is emitted.
type captureLogger struct {
	logger.ContextLogger
	access sync.Mutex
	warns  []string
}

func (l *captureLogger) Warn(args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	var sb strings.Builder
	for _, a := range args {
		if s, ok := a.(string); ok {
			sb.WriteString(s)
		}
	}
	l.warns = append(l.warns, sb.String())
}

func (l *captureLogger) warnText() string {
	l.access.Lock()
	defer l.access.Unlock()
	return strings.Join(l.warns, "\n")
}

// ECH whose config list must be fetched over DNS cannot work on any consumer
// that goes through STDConfig() — i.e. every QUIC consumer (hysteria2/tuic via
// sing-quic, DoQ/DoH3 resolvers): they never call our ClientHandshake, which is
// the only place the fetch happens. That is a SILENT privacy downgrade (user
// believes the SNI is hidden), so it must be said out loud. (Audit 2026-07-30.)
func TestECHClientConfig_STDConfigWarnsWhenFetchCannotHappen(t *testing.T) {
	log := &captureLogger{}
	cfg, err := NewSTDClient(context.Background(), log, "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		// No inline Config and no ConfigPath => the DNS-fetch flow => ECHClientConfig.
		ECH: &option.OutboundECHOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewSTDClient: %v", err)
	}
	echConfig, ok := cfg.(*ECHClientConfig)
	if !ok {
		t.Fatalf("expected *ECHClientConfig for DNS-fetched ECH, got %T", cfg)
	}
	if got := log.warnText(); got != "" {
		t.Fatalf("nothing should be warned before STDConfig is called, got %q", got)
	}

	// The QUIC path: take the std config and run the handshake yourself.
	if _, err := echConfig.STDConfig(); err != nil {
		t.Fatalf("STDConfig must still succeed (degrade loudly, never fail): %v", err)
	}
	warn := log.warnText()
	if !strings.Contains(warn, "ECH") {
		t.Errorf("STDConfig on DNS-fetched ECH must warn, got %q", warn)
	}
	if !strings.Contains(warn, "example.com") {
		t.Errorf("warning must name the server so the user can act on it, got %q", warn)
	}

	// Warn once per config, not once per connection — sing-quic calls STDConfig
	// on every client build and this would otherwise flood the Logs tab.
	before := len(log.warns)
	for i := 0; i < 5; i++ {
		if _, err := echConfig.STDConfig(); err != nil {
			t.Fatalf("STDConfig: %v", err)
		}
	}
	if len(log.warns) != before {
		t.Errorf("warning must be emitted once, got %d extra", len(log.warns)-before)
	}
}

// Sibling-маркер: an INLINE ECH config list works fine over QUIC — the list is
// already on the std config, no fetch is needed — so it must NOT be warned at,
// and must not even produce an ECHClientConfig. Guards the gate from widening
// into "ECH always warns on QUIC", which would be false and would train users
// to ignore the line.
func TestECHClientConfig_InlineConfigIsSilent(t *testing.T) {
	// A syntactically valid, minimal ECH CONFIGS PEM ("AAAA" -> 3 zero bytes).
	const inlinePEM = "-----BEGIN ECH CONFIGS-----\nAAAA\n-----END ECH CONFIGS-----"
	log := &captureLogger{}
	cfg, err := NewSTDClient(context.Background(), log, "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		ECH: &option.OutboundECHOptions{
			Enabled: true,
			Config:  []string{inlinePEM},
		},
	})
	if err != nil {
		t.Fatalf("NewSTDClient with inline ECH: %v", err)
	}
	if _, isFetch := cfg.(*ECHClientConfig); isFetch {
		t.Fatal("inline ECH must not use the DNS-fetch wrapper")
	}
	if _, err := cfg.STDConfig(); err != nil {
		t.Fatalf("STDConfig: %v", err)
	}
	if got := log.warnText(); got != "" {
		t.Errorf("inline ECH works over QUIC and must stay silent, got %q", got)
	}
}
