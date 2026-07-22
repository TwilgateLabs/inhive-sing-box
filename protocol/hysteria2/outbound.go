package hysteria2

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
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.Hysteria2OutboundOptions](registry, C.TypeHysteria2, NewOutbound)
}

var (
	_ adapter.Outbound                = (*tuic.Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*tuic.Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	client *hysteria2.Client
	// clientOptions — точная копия опций, которыми построен боевой client.
	// InHive: fresh-проба (adapter.ProbeFreshDialer) поднимает из них
	// ТРАНЗИЕНТНЫЙ клиент, чтобы честно проверить, встаёт ли НОВАЯ QUIC-сессия
	// (боевую сессию h.client переиспользует DialContext, и после смены сети
	// она врёт зелёным).
	clientOptions hysteria2.ClientOptions
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2OutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	var salamanderPassword string
	if options.Obfs != nil {
		if options.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		switch options.Obfs.Type {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = options.Obfs.Password
		default:
			return nil, E.New("unknown obfs type: ", options.Obfs.Type)
		}
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	networkList := options.Network.Build()
	clientOptions := hysteria2.ClientOptions{
		Context:            ctx,
		Dialer:             outboundDialer,
		Logger:             logger,
		BrutalDebug:        options.BrutalDebug,
		ServerAddress:      options.ServerOptions.Build(),
		ServerPorts:        options.ServerPorts,
		HopInterval:        time.Duration(options.HopInterval),
		SendBPS:            uint64(options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:         uint64(options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword: salamanderPassword,
		Password:           options.Password,
		TLSConfig:          tlsConfig,
		UDPDisabled:        !common.Contains(networkList, N.NetworkUDP),
	}
	client, err := hysteria2.NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:       outbound.NewAdapterWithDialerOptions(C.TypeHysteria2, tag, networkList, options.DialerOptions),
		logger:        logger,
		client:        client,
		clientOptions: clientOptions,
	}, nil
}

// DialProbeFresh — см. adapter.ProbeFreshDialer. hysteria2 держит ОДНУ
// QUIC-сессию в h.client и переиспользует её в DialContext; после смены сети
// она отвечает зелёным с протухшего пула. Для пробы поднимаем ТРАНЗИЕНТНЫЙ
// клиент из тех же опций (свой QUIC-хендшейк), дайлим по нему и закрываем его
// вместе с conn'ом. Боевой h.client не трогаем. Только TCP-проба; UDP — падаем
// на обычный путь (пробы урлтеста всегда TCP).
func (h *Outbound) DialProbeFresh(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return h.DialContext(ctx, network, destination)
	}
	probeClient, err := hysteria2.NewClient(h.clientOptions)
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
		conn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx)
}

func (h *Outbound) InterfaceUpdated() {
	h.client.CloseWithError(E.New("network changed"))
}

func (h *Outbound) Close() error {
	return h.client.CloseWithError(os.ErrClosed)
}
