package trojan

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TrojanOutboundOptions](registry, C.TypeTrojan, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	serverAddr      M.Socksaddr
	key             [56]byte
	multiplexDialer *mux.Client
	tlsConfig       tls.Config
	tlsDialer       tls.Dialer
	transport       adapter.V2RayClientTransport
	// transportOptions — опции боевого transport'а для fresh-пробы: транзиентный
	// транспорт со СВОИМ xmux/h2/h3-пулом (xhttp пулит независимо от sing-mux).
	transportOptions *option.V2RayTransportOptions
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeTrojan, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		key:        trojan.Key(options.Password),
	}
	if options.TLS != nil {
		outbound.tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
			Context:       ctx,
			Logger:        logger,
			ServerAddress: options.Server,
			Options:       common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled,
		})
		if err != nil {
			return nil, err
		}
		outbound.tlsDialer = tls.NewDialer(outboundDialer, outbound.tlsConfig)
	}
	if options.Transport != nil {
		outbound.transport, err = v2ray.NewClientTransport(ctx, logger, outbound.dialer, outbound.serverAddr, common.PtrValueOrDefault(options.Transport), outbound.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
		outbound.transportOptions = options.Transport // для fresh-пробы (транзиентный транспорт)
	}
	outbound.multiplexDialer, err = mux.NewClientWithOptions((*trojanDialer)(outbound), logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	return outbound, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.multiplexDialer == nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		return (*trojanDialer)(h).DialContext(ctx, network, destination)
	} else {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		}
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
}

// DialProbeFresh — см. adapter.ProbeFreshDialer. Закрывает два переиспользуемых
// слоя: (1) sing-mux сессию — обход прямым протокол-дайлером (inner trojanDialer,
// пул не трогается); (2) xhttp xmux h2/h3-пул в h.transport — для пробы
// поднимаем ТРАНЗИЕНТНЫЙ транспорт (свой пул, дефолты идентичны боевому) и
// дайлим trojan-хендшейк через shallow-клон Outbound с подменённым transport
// (боевой h.transport не трогаем). Транзиент закрывается вместе с probe-conn.
// Без транспорта — прямой inner dialer, естественно свежий.
func (h *Outbound) DialProbeFresh(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.transport == nil {
		return (*trojanDialer)(h).DialContext(ctx, network, destination)
	}
	freshTransport, err := v2ray.NewClientTransport(ctx, h.logger, h.dialer, h.serverAddr, common.PtrValueOrDefault(h.transportOptions), h.tlsConfig)
	if err != nil {
		return nil, err
	}
	if freshTransport == nil {
		return (*trojanDialer)(h).DialContext(ctx, network, destination)
	}
	probe := *h
	probe.transport = freshTransport
	conn, err := (*trojanDialer)(&probe).DialContext(ctx, network, destination)
	if err != nil {
		_ = freshTransport.Close()
		return nil, err
	}
	return &adapter.ProbeConn{Conn: conn, OnClose: func() error {
		return freshTransport.Close()
	}}, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.multiplexDialer == nil {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*trojanDialer)(h).ListenPacket(ctx, destination)
	} else {
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
}

func (h *Outbound) InterfaceUpdated() {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) Close() error {
	return common.Close(common.PtrOrNil(h.multiplexDialer), h.transport)
}

type trojanDialer Outbound

func (h *trojanDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return trojan.NewClientConn(conn, h.key, destination), nil
	case N.NetworkUDP:
		return bufio.NewBindPacketConn(trojan.NewClientPacketConn(conn, h.key), destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *trojanDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return conn.(net.PacketConn), nil
}

// ProbeAfterSleep — adapter.SleepProber: делегирует транспорту (xhttp), если он
// умеет проверять свои пулы; остальные транспорты/plain-TLS — нечего проверять.
// InHive 2026-09-08, см. v2/hcore/pause.go.
func (h *Outbound) ProbeAfterSleep(ctx context.Context) (probed int, closed int) {
	if prober, ok := h.transport.(adapter.SleepProber); ok {
		return prober.ProbeAfterSleep(ctx)
	}
	return 0, 0
}
