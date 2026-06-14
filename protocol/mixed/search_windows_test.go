package mixed

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/process"

	N "github.com/sagernet/sing/common/network"
)

// TestProcessSearcherResolvesLocalConn verifies the Windows process searcher —
// the runtime link the gate depends on — can resolve a live local TCP
// connection's source endpoint to the owning process. If this fails, the gate
// returns false at runtime (the browser dialog reappears) regardless of the
// signature logic, because newConnection never reaches browserBypassAllowed.
func TestProcessSearcherResolvesLocalConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, e := ln.Accept()
		ch <- accepted{c, e}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	defer a.conn.Close()

	// The accepted conn's RemoteAddr is the dialer's local endpoint = THIS test
	// process's socket — the same shape as a browser connecting to the proxy.
	source, err := netip.ParseAddrPort(a.conn.RemoteAddr().String())
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}

	searcher, err := process.NewSearcher(process.Config{})
	if err != nil {
		t.Fatalf("searcher init failed (gate would be disabled): %v", err)
	}

	owner, err := searcher.FindProcessInfo(context.Background(), N.NetworkTCP, source, netip.AddrPort{})
	if err != nil {
		t.Fatalf("FindProcessInfo failed (gate would return false at runtime): %v", err)
	}
	if owner == nil || owner.ProcessPath == "" {
		t.Fatalf("searcher returned no process path — gate can't identify the connecting app")
	}
	t.Logf("searcher resolved %s -> pid=%d path=%s", source, owner.ProcessID, owner.ProcessPath)
}
