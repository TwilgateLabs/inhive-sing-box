// daita dialer wrapper — stub (all builds).
// The actual CGo code lives in daita.go (build tag: daita).
package daita

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// contextKey is the key used to store a DAITA Framework in context.
type contextKey struct{}

// WithFramework stores fw in ctx.
func WithFramework(ctx context.Context, fw *Framework) context.Context {
	return service.ContextWith[*Framework](ctx, fw)
}

// FrameworkFromContext retrieves a DAITA Framework from ctx (nil if absent).
func FrameworkFromContext(ctx context.Context) *Framework {
	return service.FromContext[*Framework](ctx)
}

// WrapDialer wraps d so that every outbound TCP connection is passed through
// the DAITA framework for padding injection. Returns d unchanged if fw is nil.
func WrapDialer(d N.Dialer, fw *Framework) N.Dialer {
	if fw == nil {
		return d
	}
	return &daitaDialer{Dialer: d, fw: fw}
}

type daitaDialer struct {
	N.Dialer
	fw *Framework
}

func (d *daitaDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return Wrap(conn, d.fw), nil
}
