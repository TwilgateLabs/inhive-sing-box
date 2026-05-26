//go:build with_olcrtc

// Package olcrtc реализует sing-box outbound поверх github.com/openlibrecommunity/olcrtc —
// stealth tunnel через легальные WebRTC SFU (jitsi/wbstream/telemost). См.
// project_olcrtc_scope.md для полного контекста (3-carrier failover, mode switching, etc).
//
// 🚨 STATUS 2026-05-26: ARCHITECTURALLY BROKEN — DialContext returns ErrNotImplemented.
//
// Phase 1 (this file) was written under the misconception that pkg/olcrtc.Session
// supports multiple concurrent net.Conn. It does NOT — Session is a single-stream
// API: all conn{} instances returned by Session.Dial() share one io.Pipe (pr/pw)
// and one inner.Send channel. Multiple sing-box streams via this wrapper would:
//   - Cross-contaminate traffic (TLS bytes of stream A delivered to stream B → decrypt errors)
//   - Leak goroutines per Dial (each spawns go inner.WatchConnection(ctx))
//   - Overwrite SetEndedCallback on every Dial (only last gets ended signal)
//
// Upstream's correct multiplexing pattern lives in internal/client/client.go:216-217:
//   conn = muxconn.New(ln, cipher)     // encryption layer
//   sess = smux.Client(conn, ...)      // smux multiplexing
//   control = openControlStream(...)   // handshake
// But muxconn / handshake are in internal/ — not accessible without forking upstream.
//
// Server-side pkg/olcrtc/tunnel.Server exists as proper public API; client-side
// equivalent does not. See:
//   - memory/project_olcrtc_implementation.md "H-1" section for full analysis
//   - memory/audit_olcrtc_2026_05_26.md (security review)
//
// Resolution path: fork upstream → expose internal/client as pkg/olcrtc/client.
// Until that's done, Start() returns an explicit error to prevent silent breakage.
package olcrtc

import (
	"context"
	"net"

	// upstream "github.com/openlibrecommunity/olcrtc/pkg/olcrtc" — re-import when
	// wrapper rewrite is done. Kept in go.mod so go.sum hash stays pinned;
	// import re-added when Start() is reconnected to upstream.New + session.Connect.
	_ "github.com/openlibrecommunity/olcrtc/pkg/olcrtc"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// RegisterOutbound регистрирует "olcrtc" outbound type в sing-box registry.
// Вызывается из include/olcrtc_outbound.go (только с build tag with_olcrtc).
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.OLCRTCOutboundOptions](registry, C.TypeOLCRTC, NewOutbound)
}

// Outbound — sing-box adapter (Phase 1 SKELETON). Session intentionally not stored
// until wrapper rewrite (see package doc). TCP-only by design (UDP не поддерживается).
//
// ctx + logger kept as fields for wrapper rewrite — when Start() reconnects to
// upstream.New(ctx, ...), we need the original ctx (DialerOptions ctx layering)
// not the per-call ctx.
type Outbound struct {
	outbound.Adapter
	ctx    context.Context //nolint:unused // see struct doc
	logger logger.ContextLogger
}

// NewOutbound валидирует config но НЕ создаёт upstream.Session — пока wrapper
// architecturally broken (см. package doc), не открываем network handles.
// Validation still happens to give user proper config feedback at parse time.
func NewOutbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.OLCRTCOutboundOptions,
) (adapter.Outbound, error) {
	if options.RoomID == "" {
		return nil, E.New("room_id is required for olcrtc outbound")
	}
	// Либо AuthProvider, либо direct Engine+URL+Token
	if options.AuthProvider == "" && options.Engine == "" {
		return nil, E.New("either auth_provider or engine is required for olcrtc outbound")
	}
	if options.Engine != "" && (options.URL == "" || options.Token == "") {
		return nil, E.New("direct engine mode requires both url and token")
	}

	// Не вызываем upstream.New / RegisterDefaults — выждем до rewrite чтобы:
	//   - Не делать auth.Get → HTTP request к auth provider (network IO без user intent)
	//   - Не allocать pion/livekit stacks (RAM на iOS NE Provider 15MB budget)
	//   - Никаких goroutines в background
	logger.Warn("olcrtc outbound config accepted but Start() will fail — see package doc")

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(
			C.TypeOLCRTC, tag, []string{N.NetworkTCP}, options.DialerOptions,
		),
		ctx:    ctx,
		logger: logger,
	}, nil
}

// Start: до Phase 2.5 rewrite — возвращает ErrNotImplemented чтобы предотвратить
// silent traffic corruption. Reason: pkg/olcrtc.Session API single-stream; multiple
// DialContext calls would cross-contaminate traffic. См. package doc.
//
// Когда wrapper будет переписан (fork upstream + smux multiplexing), эта функция
// снова делает session.Connect(). Пока — fail loud.
func (o *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	// IMPORTANT: do NOT call o.session.Connect() — would establish WebRTC link
	// that subsequent DialContext can't safely multiplex. Fail before allocating.
	return E.New(
		"olcrtc outbound is architecturally incomplete: pkg/olcrtc.Session is " +
			"single-stream API, sing-box requires per-stream multiplexing. " +
			"Tracked in memory/audit_olcrtc_2026_05_26.md (H-1). " +
			"Resolution: fork olcrtc + expose internal/client as public package, " +
			"OR embed smux+handshake ourselves (requires matching custom server).",
	)
}

// DialContext: would silently corrupt traffic if Start() were not gated.
// Returns ErrNotImplemented as defence-in-depth even if Start logic changes.
func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	_ = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return nil, E.New("olcrtc DialContext not implemented — see Start() error and package doc")
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

// ListenPacket — UDP не поддерживается. WebRTC data channel reliable+ordered,
// UDP datagram semantic несовместима. Юзеры UDP трафика должны использовать
// другой outbound (или UDP-over-TCP wrapper в Phase 2).
func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("UDP is not supported by olcrtc outbound")
}

// Close no-op пока NewOutbound не создаёт session (см. package doc).
// После wrapper rewrite — закроет smux session + WebRTC session.
func (o *Outbound) Close() error {
	return nil
}
