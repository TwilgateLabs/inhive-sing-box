package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// plainProbeDialer реализует только N.Dialer (без ProbeFreshDialer).
type plainProbeDialer struct {
	target   string
	dialCtx  atomic.Int32
	dialFrsh atomic.Int32
}

func (d *plainProbeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dialCtx.Add(1)
	return net.Dial("tcp", d.target)
}

func (d *plainProbeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// freshProbeDialer дополнительно реализует adapter.ProbeFreshDialer.
type freshProbeDialer struct {
	plainProbeDialer
}

func (d *freshProbeDialer) DialProbeFresh(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dialFrsh.Add(1)
	return net.Dial("tcp", d.target)
}

// TestURLTestFreshRouting — fresh-флаг из контекста маршрутизирует пробу на
// DialProbeFresh, если outbound его реализует; иначе (и без флага) — обычный
// DialContext. Апстрим-поведение без флага не меняется.
func TestURLTestFreshRouting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	target := srv.Listener.Addr().String()
	link := srv.URL

	// 1. Без fresh-флага: пулящийся outbound всё равно дайлит через DialContext.
	fd := &freshProbeDialer{plainProbeDialer{target: target}}
	if _, err := URLTest(context.Background(), link, fd); err != nil {
		t.Fatalf("URLTest (no fresh) error: %v", err)
	}
	if fd.dialCtx.Load() != 1 || fd.dialFrsh.Load() != 0 {
		t.Fatalf("no-fresh: expected DialContext=1 DialProbeFresh=0, got %d/%d",
			fd.dialCtx.Load(), fd.dialFrsh.Load())
	}

	// 2. С fresh-флагом и реализованным ProbeFreshDialer: идём через DialProbeFresh.
	fd2 := &freshProbeDialer{plainProbeDialer{target: target}}
	if _, err := URLTest(ContextWithProbeFresh(context.Background()), link, fd2); err != nil {
		t.Fatalf("URLTest (fresh) error: %v", err)
	}
	if fd2.dialFrsh.Load() != 1 || fd2.dialCtx.Load() != 0 {
		t.Fatalf("fresh+capable: expected DialProbeFresh=1 DialContext=0, got %d/%d",
			fd2.dialCtx.Load(), fd2.dialFrsh.Load())
	}

	// 3. С fresh-флагом, но outbound НЕ реализует ProbeFreshDialer: fallback на
	//    DialContext (плоский протокол и так дайлит свежо).
	pd := &plainProbeDialer{target: target}
	if _, err := URLTest(ContextWithProbeFresh(context.Background()), link, pd); err != nil {
		t.Fatalf("URLTest (fresh, plain) error: %v", err)
	}
	if pd.dialCtx.Load() != 1 {
		t.Fatalf("fresh+plain: expected DialContext=1, got %d", pd.dialCtx.Load())
	}
}
