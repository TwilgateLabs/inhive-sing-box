package xhttp

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// probeStubDialer — N.Dialer, который в конструкторе xhttp.NewClient не
// вызывается (пул ленивый), поэтому дайл-методы просто возвращают ошибку.
type probeStubDialer struct{}

func (probeStubDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (probeStubDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// TestTransientClientPoolIsolation — инвариант fresh-пробы: транзиентный
// xhttp.Client (тот, что строит vless/vmess/trojan DialProbeFresh через
// v2ray.NewClientTransport) держит СВОЙ xmux-пул, изолированный от боевого.
// Close() транзиента ресетит только его пул и не затрагивает боевой.
func TestTransientClientPoolIsolation(t *testing.T) {
	opts := option.V2RayXHTTPOptions{}
	serverAddr := M.ParseSocksaddr("example.com:443")
	tlsCfg := plainTLS(t)

	live, err := NewClient(context.Background(), probeStubDialer{}, serverAddr, opts, tlsCfg)
	if err != nil {
		t.Fatalf("build live client: %v", err)
	}
	transient, err := NewClient(context.Background(), probeStubDialer{}, serverAddr, opts, tlsCfg)
	if err != nil {
		t.Fatalf("build transient client: %v", err)
	}

	liveC, ok := live.(*Client)
	if !ok {
		t.Fatalf("live is not *Client: %T", live)
	}
	transientC, ok := transient.(*Client)
	if !ok {
		t.Fatalf("transient is not *Client: %T", transient)
	}

	// Изоляция: разные экземпляры менеджера пула.
	if liveC.xmuxManager == transientC.xmuxManager {
		t.Fatal("transient shares xmuxManager with live client — пробный пул НЕ изолирован")
	}

	// Close транзиента безопасен, идемпотентен и не затрагивает боевой менеджер.
	if err := transientC.Close(); err != nil {
		t.Fatalf("transient Close returned error: %v", err)
	}
	if err := transientC.Close(); err != nil {
		t.Fatalf("transient double-Close returned error: %v", err)
	}
	if liveC.xmuxManager == nil {
		t.Fatal("live xmuxManager обнулён после Close транзиента — боевой пул затронут")
	}
}
