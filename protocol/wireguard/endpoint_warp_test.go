package wireguard

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// warpConfig builds a minimal VALID config, which each subtest then breaks.
func warpConfig() *C.WARPConfig {
	config := &C.WARPConfig{PrivateKey: "private-key"}
	config.Interface.Addresses.V4 = "172.16.0.2"
	config.Interface.Addresses.V6 = "2606:4700:110:8888::1"
	config.Peers = make([]struct {
		PublicKey string `json:"public_key"`
		Endpoint  struct {
			V4    string `json:"v4"`
			V6    string `json:"v6"`
			Host  string `json:"host"`
			Ports []int  `json:"ports"`
		} `json:"endpoint"`
	}, 1)
	config.Peers[0].PublicKey = "public-key"
	config.Peers[0].Endpoint.Host = "engage.cloudflareclient.com:2408"
	config.Peers[0].Endpoint.Ports = []int{2408}
	return config
}

// TestWARPStartHandlerMalformedConfig reproduces the process-kill class found
// in the 2026-08-16 endpoint audit: startHandler runs via `go w.startHandler()`,
// and before the validateWARPConfig gate each of these configs panicked there —
// config.Peers[0] (index out of range) or netip.MustParsePrefix — an
// unrecoverable crash of the whole process, triggered by a user-supplied or
// cached warp_config. With the gate, startHandler must return cleanly and the
// endpoint must stay uninitialized (DialContext errors instead of the app dying).
//
// Every config here has a non-empty PrivateKey ON PURPOSE: that is what routes
// it past the fetch-fresh-profile branch (no network in this test) straight
// into the construction code that used to panic.
func TestWARPStartHandlerMalformedConfig(t *testing.T) {
	noPeers := warpConfig()
	noPeers.Peers = nil

	badV4 := warpConfig()
	badV4.Interface.Addresses.V4 = ""

	badV6 := warpConfig()
	badV6.Interface.Addresses.V6 = "not-an-address"

	for name, config := range map[string]*C.WARPConfig{
		"no_peers": noPeers,
		"bad_v4":   badV4,
		"bad_v6":   badV6,
	} {
		t.Run(name, func(t *testing.T) {
			ep, err := NewWARPEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "warp-test",
				option.WireGuardWARPEndpointOptions{WARPConfig: config})
			if err != nil {
				t.Fatalf("NewWARPEndpoint: %v", err)
			}
			w := ep.(*WARPEndpoint)
			w.startHandler() // old code: panic here → SIGSEGV-class process kill
			if w.isEndpointInitialized() {
				t.Fatal("endpoint must stay uninitialized on malformed config")
			}
			if _, err := w.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80")); err == nil {
				t.Fatal("DialContext must error on uninitialized endpoint")
			}
		})
	}
}

// rand.Intn(0) panics; the old inline port selection did exactly that for an
// empty ports list. pickWARPPeerPort must never panic and must honor the
// override > ports > host-embedded-port > default priority.
func TestPickWARPPeerPort(t *testing.T) {
	if got := pickWARPPeerPort(500, []int{2408}, []string{"host", "1000"}); got != 500 {
		t.Fatalf("override must win, got %d", got)
	}
	if got := pickWARPPeerPort(0, []int{939}, []string{"host"}); got != 939 {
		t.Fatalf("advertised port must be used, got %d", got)
	}
	if got := pickWARPPeerPort(0, nil, []string{"engage.cloudflareclient.com", "1701"}); got != 1701 {
		t.Fatalf("host-embedded port must be used, got %d", got)
	}
	// The crash shape: no override, empty ports, host without a port.
	if got := pickWARPPeerPort(0, nil, []string{"engage.cloudflareclient.com"}); got != 2408 {
		t.Fatalf("default port expected, got %d", got)
	}
	if got := pickWARPPeerPort(0, nil, []string{"host", "not-a-port"}); got != 2408 {
		t.Fatalf("unparsable host port must fall back to default, got %d", got)
	}
}

func TestValidateWARPConfig(t *testing.T) {
	if err := validateWARPConfig(warpConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := validateWARPConfig(nil); err == nil {
		t.Fatal("nil config accepted")
	}
	noKey := warpConfig()
	noKey.PrivateKey = ""
	if err := validateWARPConfig(noKey); err == nil {
		t.Fatal("empty private key accepted")
	}
	noPublic := warpConfig()
	noPublic.Peers[0].PublicKey = ""
	if err := validateWARPConfig(noPublic); err == nil {
		t.Fatal("empty peer public key accepted")
	}
}
