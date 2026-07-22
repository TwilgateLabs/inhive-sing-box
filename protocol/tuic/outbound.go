package tuic

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/gofrs/uuid/v5"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TUICOutboundOptions](registry, C.TypeTUIC, NewOutbound)
}

var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger    logger.ContextLogger
	client    *tuic.Client
	udpStream bool
	// clientOptions — точная копия опций боевого client. InHive: fresh-проба
	// (adapter.ProbeFreshDialer) поднимает из них ТРАНЗИЕНТНЫЙ клиент, чтобы
	// честно проверить новую QUIC-сессию (боевую h.client переиспользует
	// DialContext → врёт зелёным после смены сети).
	clientOptions tuic.ClientOptions
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	userUUID, err := uuid.FromString(options.UUID)
	if err != nil {
		return nil, E.Cause(err, "invalid uuid")
	}
	var tuicUDPStream bool
	if options.UDPOverStream && options.UDPRelayMode != "" {
		return nil, E.New("udp_over_stream is conflict with udp_relay_mode")
	}
	switch options.UDPRelayMode {
	case "native":
	case "quic":
		tuicUDPStream = true
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	clientOptions := tuic.ClientOptions{
		Context:           ctx,
		Dialer:            outboundDialer,
		ServerAddress:     options.ServerOptions.Build(),
		TLSConfig:         tlsConfig,
		UUID:              userUUID,
		Password:          options.Password,
		CongestionControl: options.CongestionControl,
		UDPStream:         tuicUDPStream,
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(options.Heartbeat),
	}
	client, err := tuic.NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:       outbound.NewAdapterWithDialerOptions(C.TypeTUIC, tag, options.Network.Build(), options.DialerOptions),
		logger:        logger,
		client:        client,
		udpStream:     options.UDPOverStream,
		clientOptions: clientOptions,
	}, nil
}

// DialProbeFresh — см. adapter.ProbeFreshDialer. tuic держит ОДНУ QUIC-сессию в
// h.client и переиспользует её в DialContext; после смены сети она врёт
// зелёным. Для пробы поднимаем ТРАНЗИЕНТНЫЙ клиент из тех же опций (свой
// QUIC-хендшейк), дайлим по нему и закрываем вместе с conn'ом. Боевой h.client
// не трогаем. Только TCP-проба; UDP — на обычный путь.
func (h *Outbound) DialProbeFresh(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return h.DialContext(ctx, network, destination)
	}
	probeClient, err := tuic.NewClient(h.clientOptions)
	if err != nil {
		return nil, err
	}
	conn, err := probeClient.DialConn(ctx, destination)
	if err != nil {
		_ = probeClient.CloseWithError(os.ErrClosed)
		return nil, err
	}
	return &adapter.ProbeConn{Conn: conn, OnClose: func() error {
		return probeClient.CloseWithError(os.ErrClosed)
	}}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialConn(ctx, destination)
	case N.NetworkUDP:
		if h.udpStream {
			h.logger.InfoContext(ctx, "outbound stream packet connection to ", destination)
			streamConn, err := h.client.DialConn(ctx, uot.RequestDestination(uot.Version))
			if err != nil {
				return nil, err
			}
			return uot.NewLazyConn(streamConn, uot.Request{
				IsConnect:   true,
				Destination: destination,
			}), nil
		} else {
			conn, err := h.ListenPacket(ctx, destination)
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(conn, destination), nil
		}
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.udpStream {
		h.logger.InfoContext(ctx, "outbound stream packet connection to ", destination)
		streamConn, err := h.client.DialConn(ctx, uot.RequestDestination(uot.Version))
		if err != nil {
			return nil, err
		}
		return uot.NewLazyConn(streamConn, uot.Request{
			IsConnect:   false,
			Destination: destination,
		}), nil
	} else {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return h.client.ListenPacket(ctx)
	}
}

func (h *Outbound) InterfaceUpdated() {
	_ = h.client.CloseWithError(E.New("network changed"))
}

func (h *Outbound) Close() error {
	return h.client.CloseWithError(os.ErrClosed)
}
