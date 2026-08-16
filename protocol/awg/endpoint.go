package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/awg"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"go4.org/netipx"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register(registry, constant.TypeAwg, NewEndpoint)
}

type Endpoint struct {
	*awg.Device
	endpoint.Adapter
	address   []netip.Prefix
	router    adapter.Router
	logger    log.ContextLogger
	dnsRouter adapter.DNSRouter
	started   bool
	ctx       context.Context
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Endpoint, error) {
	if options.MTU == 0 {
		options.MTU = 1408
	}

	options.UDPFragmentDefault = true
	dial, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: false,
		DirectOutbound: true,
	})
	if err != nil {
		return nil, err
	}

	var allowedPrefixBuilder netipx.IPSetBuilder
	var excludedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}

		if addr, err := netip.ParseAddr(peer.Address); err == nil {
			excludedPrefixBuilder.Add(addr)
		}
	}
	allowedIps, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	excludedIps, err := excludedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}

	ipc, err := genIpcConfig(options)
	if err != nil {
		return nil, err
	}

	// Cloudflare/WARP reserved bytes cannot go through the WireGuard UAPI, so
	// they are injected in the bind at send time. Take them from the first peer
	// that defines exactly 3 bytes.
	var (
		reserved    [3]byte
		hasReserved bool
	)
	for _, peer := range options.Peers {
		if len(peer.Reserved) == 3 {
			copy(reserved[:], peer.Reserved)
			hasReserved = true
			break
		}
	}

	dev, err := awg.NewDevice(ctx, logger, dial, ipc, awg.DeviceOpts{
		UseIntegratedTun: options.UseIntegratedTun,
		Address:          options.Address,
		AllowedIps:       allowedIps.Prefixes(),
		ExcludedIps:      excludedIps.Prefixes(),
		MTU:              options.MTU,
		Reserved:         reserved,
		HasReserved:      hasReserved,
	})
	if err != nil {
		return nil, err
	}

	return &Endpoint{
		Device:  dev,
		Adapter: endpoint.NewAdapterWithDialerOptions("awg", tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		address: options.Address,
		router:  router,
		logger:  logger,
		ctx:     ctx,
	}, nil
}

func genIpcConfig(opts option.AwgEndpointOptions) (string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
	if err != nil {
		return "", err
	}
	s := "private_key=" + hex.EncodeToString(privateKeyBytes)
	if opts.ListenPort != 0 {
		s += "\nlisten_port=" + format.ToString(opts.ListenPort)
	}
	if opts.Jc != 0 {
		s += "\njc=" + format.ToString(opts.Jc)
	}
	if opts.Jmin != 0 {
		s += "\njmin=" + format.ToString(opts.Jmin)
	}
	if opts.Jmax != 0 {
		s += "\njmax=" + format.ToString(opts.Jmax)
	}
	if opts.S1 != 0 {
		s += "\ns1=" + format.ToString(opts.S1)
	}
	if opts.S2 != 0 {
		s += "\ns2=" + format.ToString(opts.S2)
	}
	// s3/s4 (message-padding sizes) are only a valid UAPI key on amneziawg-go
	// v0.2.x. v1.0.x dropped them, and emitting an unknown key aborts the whole
	// IpcSet. Gate emission so a config carrying s3/s4 stays parseable across the
	// version bump (the values are still parsed and stored, just not emitted when
	// the linked runtime would reject them). See capability.go.
	if !awgRuntimeSupportsControlledJunk {
		if opts.S3 != 0 {
			s += "\ns3=" + format.ToString(opts.S3)
		}
		if opts.S4 != 0 {
			s += "\ns4=" + format.ToString(opts.S4)
		}
	}
	if opts.H1 != "" {
		s += "\nh1=" + opts.H1
	}
	if opts.H2 != "" {
		s += "\nh2=" + opts.H2
	}
	if opts.H3 != "" {
		s += "\nh3=" + opts.H3
	}
	if opts.H4 != "" {
		s += "\nh4=" + opts.H4
	}
	if opts.I1 != "" {
		s += "\ni1=" + opts.I1
	}
	if opts.I2 != "" {
		s += "\ni2=" + opts.I2
	}
	if opts.I3 != "" {
		s += "\ni3=" + opts.I3
	}
	if opts.I4 != "" {
		s += "\ni4=" + opts.I4
	}
	if opts.I5 != "" {
		s += "\ni5=" + opts.I5
	}

	// AmneziaWG 1.5 controlled-junk generators (j1/j2/j3) and inter-handshake
	// timeout (itime) are only a valid UAPI key on amneziawg-go >= v1.0.0. On
	// v0.2.x they hit the `default:` case and abort IpcSet, so emit them only
	// when the linked runtime supports them. See capability.go.
	if awgRuntimeSupportsControlledJunk {
		if opts.J1 != "" {
			s += "\nj1=" + opts.J1
		}
		if opts.J2 != "" {
			s += "\nj2=" + opts.J2
		}
		if opts.J3 != "" {
			s += "\nj3=" + opts.J3
		}
		if opts.Itime != 0 {
			s += "\nitime=" + format.ToString(opts.Itime)
		}
	}

	for _, peer := range opts.Peers {
		publicKeyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil {
			return "", err
		}
		s += "\npublic_key=" + hex.EncodeToString(publicKeyBytes)
		if peer.PresharedKey != "" {
			presharedKeyBytes, err := base64.StdEncoding.DecodeString(peer.PresharedKey)
			if err != nil {
				return "", err
			}
			s += "\npreshared_key=" + hex.EncodeToString(presharedKeyBytes)
		}
		if peer.Address != "" && peer.Port != 0 {
			s += "\nendpoint=" + peer.Address + ":" + format.ToString(peer.Port)
		}
		if peer.PersistentKeepaliveInterval != 0 {
			s += "\npersistent_keepalive_interval=" + format.ToString(peer.PersistentKeepaliveInterval)
		}
		for _, allowedIp := range peer.AllowedIPs {
			s += "\nallowed_ip=" + allowedIp.String()
		}
	}
	return s, nil
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	metadata.Destination = destination
	for _, addr := range e.address {
		if addr.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
		}
	}
	e.logger.InfoContext(ctx, "inbound packet connection from ", source)
	e.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (w *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Source = source
	for _, addr := range w.address {
		if addr.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	w.logger.InfoContext(ctx, "inbound connection from ", source)
	w.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	w.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

// Start delegates StartStateStart to the embedded transport Device EXPLICITLY.
// This method shadows the promoted (*awg.Device).Start, so without the explicit
// call the amneziawg device was never created (no IpcSet, no tun start, no Up):
// the tunnel could never handshake, and Close() dereferenced the nil awgDevice
// inside a box-close goroutine — an unrecoverable SIGSEGV that killed the whole
// process (field crash 2026-08-16: pinging an imported AmneziaWG .conf made the
// Windows app vanish without a trace).
func (o *Endpoint) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStateStart {
		return o.Device.Start(stage)
	}
	if stage == adapter.StartStatePostStart {
		go o.readyChecker()
	}
	return nil
}

// readyChecker mirrors protocol/wireguard/endpoint.go: probe THROUGH the
// tunnel until it answers, then flip started. The old version was a blind
// 10-second timer that marked the endpoint ready unconditionally — IsReady()
// lied both ways (false for a tunnel that handshook in 1s, true for a dead
// one), which cost every awg ping the full waitDetourReady budget.
func (w *Endpoint) readyChecker() {
	for i := 0; i < 30; i++ {
		select {
		case <-w.ctx.Done():
			return
		case <-time.After(time.Second):
		}
		ctx, cancel := context.WithTimeout(w.ctx, time.Second*5)
		res, err := urltest.URLTest(ctx, "https://1.1.1.1", w)
		cancel()
		if res > 0 && res < 20000 && err == nil {
			w.started = true
			monitoring.Get(w.ctx).TestNow(w.Tag())
			return
		}
	}
}
func (w *Endpoint) IsReady() bool {
	return w.started
}
