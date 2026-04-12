// Package utproto is the sing-box adapter over the pure-Go UTProto
// transport (github.com/sagernet/sing-box/transport/utproto).
//
// All protocol-level logic lives in transport/utproto/; this file is a
// thin adapter that wires UTProto into sing-box's outbound registry.
// Forkers porting UTProto to Xray-core, Mihomo, or v2ray-core should
// copy transport/utproto/ as-is and write their own adapter mirroring
// this file against their core's outbound interface.
package utproto

import (
	"context"
	"encoding/hex"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	utproto "github.com/sagernet/sing-box/transport/utproto"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.UTProtoOutboundOptions](registry, C.TypeUTProto, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	config     *utproto.Config
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.UTProtoOutboundOptions) (adapter.Outbound, error) {
	if options.Secret == "" {
		return nil, E.New("utproto: secret is required")
	}
	if options.TLSDomain == "" {
		return nil, E.New("utproto: tls_domain is required")
	}
	secretBytes, err := hex.DecodeString(options.Secret)
	if err != nil {
		return nil, E.Cause(err, "utproto: invalid secret (expected 32 hex chars)")
	}
	if len(secretBytes) != 16 {
		return nil, E.New("utproto: secret must be 16 bytes (32 hex chars)")
	}
	var secret [16]byte
	copy(secret[:], secretBytes)

	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeUTProto, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		config: &utproto.Config{
			Secret:    secret,
			TLSDomain: options.TLSDomain,
		},
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		return nil, E.New("utproto: UDP is not supported (yet)")
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}

	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, E.Cause(err, "utproto: dial underlying connection")
	}

	conn, err := utproto.Dial(ctx, rawConn, h.config)
	if err != nil {
		common.Close(rawConn)
		return nil, E.Cause(err, "utproto: handshake")
	}
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("utproto: UDP is not supported (yet)")
}
