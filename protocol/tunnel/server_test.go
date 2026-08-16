package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Both tests below reproduce the same bug class as the AmneziaWG endpoint
// audit (2026-08-16): an early return inside a locked section leaked s.mtx,
// so ONE request naming an unknown tunnel user froze the endpoint forever —
// silent hang, no crash, no log. Before the fix these tests fail on
// TryLock (mutex still held after the error return).

func newTestServerEndpoint(t *testing.T) *ServerEndpoint {
	t.Helper()
	userKey := uuid.Must(uuid.NewV4())
	userUUID := uuid.Must(uuid.NewV4())
	return &ServerEndpoint{
		Adapter: outbound.NewAdapter(C.TypeTunnelServer, "tunnel-test", []string{N.NetworkTCP}, nil),
		logger:  log.NewNOPFactory().Logger(),
		uuid:    uuid.Must(uuid.NewV4()),
		users:   map[uuid.UUID]uuid.UUID{userKey: userUUID},
		keys:    map[uuid.UUID]uuid.UUID{userUUID: userKey},
		conns:   map[uuid.UUID]chan net.Conn{userUUID: make(chan net.Conn, 10)},
		timeout: 500 * time.Millisecond,
	}
}

func requireUnlocked(t *testing.T, s *ServerEndpoint, context string) {
	t.Helper()
	if !s.mtx.TryLock() {
		t.Fatalf("%s: s.mtx is still locked after error return — mutex leak", context)
	}
	s.mtx.Unlock()
}

func TestServerDialContextUnknownDestinationReleasesLock(t *testing.T) {
	s := newTestServerEndpoint(t)
	ctx, metadata := adapter.ExtendContext(context.Background())
	metadata.TunnelDestination = uuid.Must(uuid.NewV4()).String() // not a known user

	_, err := s.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:80"))
	if err == nil {
		t.Fatal("expected 'user not found' error for unknown tunnel destination")
	}
	requireUnlocked(t, s, "DialContext(unknown destination)")

	// The original symptom: a SECOND dial deadlocks on the leaked mutex.
	done := make(chan struct{})
	go func() {
		_, _ = s.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:80"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("second DialContext blocked forever — mutex leaked by the first error return")
	}
}

func TestServerConnHandlerUnknownUserReleasesLock(t *testing.T) {
	s := newTestServerEndpoint(t)

	var knownKey uuid.UUID
	for k := range s.users {
		knownKey = k
	}
	unknownDestination := uuid.Must(uuid.NewV4()) // != s.uuid, not in s.keys

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_ = WriteRequest(c2, &Request{
			UUID:            knownKey,
			Command:         CommandTCP,
			DestinationUUID: unknownDestination,
			Destination:     M.ParseSocksaddr("1.2.3.4:80"),
		})
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.connHandler(context.Background(), c1, adapter.InboundContext{Destination: Destination}, nil)
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected 'user not found' error for unknown destination UUID")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connHandler did not return")
	}
	requireUnlocked(t, s, "connHandler(unknown destination user)")
}
