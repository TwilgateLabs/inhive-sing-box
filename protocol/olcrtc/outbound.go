//go:build with_olcrtc

// Package olcrtc реализует sing-box outbound поверх github.com/openlibrecommunity/olcrtc —
// stealth tunnel через легальные WebRTC SFU (jitsi/wbstream/telemost). См.
// project_olcrtc_scope.md для полного контекста (3-carrier failover, mode switching, etc).
//
// Использование как embedded Go library — pkg/olcrtc/Session.Dial() возвращает net.Conn
// готовый для sing-box outbound contract. Никакого SOCKS5 listener middleware.
package olcrtc

import (
	"context"
	"net"

	upstream "github.com/openlibrecommunity/olcrtc/pkg/olcrtc"
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

// Outbound — sing-box adapter поверх olcrtc.Session. TCP only (UDP не поддерживается:
// WebRTC data channel reliable+ordered, UDP semantic incompatible).
type Outbound struct {
	outbound.Adapter
	ctx     context.Context
	logger  logger.ContextLogger
	session *upstream.Session
}

// NewOutbound создаёт olcrtc outbound из YAML/JSON config. Не подключается к SFU —
// connection отложен до Start().
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

	// Register defaults — нужно чтобы все built-in auth providers + engines были
	// доступны в upstream registry. Идемпотентно (safe to call много раз).
	upstream.RegisterDefaults()

	cfg := upstream.Config{
		Auth:      options.AuthProvider,
		RoomID:    options.RoomID,
		Engine:    options.Engine,
		URL:       options.URL,
		Token:     options.Token,
		Name:      options.Name,
		DNSServer: options.DNSServer,
		ProxyAddr: options.ProxyAddr,
		ProxyPort: options.ProxyPort,
	}

	session, err := upstream.New(ctx, cfg)
	if err != nil {
		return nil, E.Cause(err, "create olcrtc session")
	}

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(
			C.TypeOLCRTC, tag, []string{N.NetworkTCP}, options.DialerOptions,
		),
		ctx:     ctx,
		logger:  logger,
		session: session,
	}, nil
}

// Start подключается к выбранному SFU (jitsi room / wbstream / telemost). Блокирует
// до полного WebRTC handshake'а либо timeout context'а. После Start готов к DialContext.
func (o *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := o.session.Connect(o.ctx); err != nil {
		return E.Cause(err, "connect to olcrtc SFU")
	}
	o.logger.Info("olcrtc session connected")
	return nil
}

// DialContext открывает новый stream поверх существующего WebRTC data channel.
// Каждый Dial = новый smux stream внутри одной WebRTC session. Multiplexing
// прозрачен — sing-box получает обычный net.Conn.
func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "olcrtc outbound to ", destination)
		conn, err := o.session.Dial(ctx)
		if err != nil {
			return nil, E.Cause(err, "olcrtc dial")
		}
		return conn, nil
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

// Close завершает WebRTC session, освобождает все resources.
func (o *Outbound) Close() error {
	return o.session.Close()
}
