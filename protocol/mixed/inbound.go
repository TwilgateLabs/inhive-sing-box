package mixed

import (
	std_bufio "bufio"
	"context"
	"net"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"github.com/sagernet/sing/service"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.HTTPMixedInboundOptions](registry, C.TypeMixed, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router           adapter.ConnectionRouterEx
	logger           log.ContextLogger
	listener         *listener.Listener
	authenticator    *auth.Authenticator
	processSearcher  process.Searcher
	processWhitelist map[string]bool // lowercased exe basenames / android packages
	tlsConfig        tls.ServerConfig
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPMixedInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeMixed, tag),
		router:        uot.NewRouter(router, logger),
		logger:        logger,
		authenticator: auth.NewAuthenticator(options.Users),
	}
	// InHive fork: per-process auth bypass. Build the lowercased whitelist set and
	// a process searcher. Non-fatal — if the searcher can't init (e.g. restricted
	// socket diag on some Android builds), the whitelist is simply disabled and all
	// connections fall back to normal auth; startup never crashes.
	if len(options.ProcessWhitelist) > 0 {
		inbound.processWhitelist = make(map[string]bool, len(options.ProcessWhitelist))
		for _, p := range options.ProcessWhitelist {
			inbound.processWhitelist[strings.ToLower(p)] = true
		}
		searcherConfig := process.Config{Logger: logger}
		if nm := service.FromContext[adapter.NetworkManager](ctx); nm != nil {
			searcherConfig.PackageManager = nm.PackageManager()
		}
		if searcher, err := process.NewSearcher(searcherConfig); err == nil {
			inbound.processSearcher = searcher
		} else {
			logger.Warn(E.Cause(err, "mixed: process whitelist disabled, searcher init failed"))
		}
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context:        ctx,
			Logger:         logger,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: true,
		})
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	// Pass first user credentials to system proxy so browsers receive them
	// automatically and don't show an auth prompt.
	var sysProxyUser, sysProxyPass string
	if len(options.Users) > 0 {
		sysProxyUser = options.Users[0].Username
		sysProxyPass = options.Users[0].Password
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
		SetSystemProxy:    options.SetSystemProxy,
		SystemProxySOCKS:  true,
		SystemProxyUser:   sysProxyUser,
		SystemProxyPass:   sysProxyPass,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
		h.processSearcher,
	)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := h.newConnection(ctx, conn, metadata, onClose)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			return E.Cause(err, "TLS handshake")
		}
		conn = tlsConn
	}
	reader := std_bufio.NewReader(conn)
	headerBytes, err := reader.Peek(1)
	if err != nil {
		return E.Cause(err, "peek first byte")
	}
	// InHive fork: per-process auth bypass. If the connecting process is a trusted
	// browser, use a nil authenticator — nil means "no auth" in both the socks and
	// http handshakes (no 407 / AuthTypeNotRequired), so the browser connects
	// silently while every other local app still hits h.authenticator. The trust
	// decision is platform-specific (see auth_browser_{windows,other}.go): on
	// Windows it's a chain-valid Authenticode browser-vendor signature; elsewhere
	// it's the configured exe-basename / Android-package whitelist. Fully
	// non-fatal: any searcher error leaves the configured authenticator in place.
	authenticator := h.authenticator
	if h.processSearcher != nil && len(h.processWhitelist) > 0 {
		if owner, err := h.processSearcher.FindProcessInfo(ctx, N.NetworkTCP, metadata.Source.AddrPort(), metadata.Destination.AddrPort()); err == nil && owner != nil {
			if browserBypassAllowed(owner, h.processWhitelist) {
				authenticator = nil
			}
		}
	}
	switch headerBytes[0] {
	case socks4.Version, socks5.Version:
		return socks.HandleConnectionEx(ctx, conn, reader, authenticator, adapter.NewUpstreamHandlerEx(metadata, h.newUserConnection, h.streamUserPacketConnection), h.listener, 0, metadata.Source, onClose)
	default:
		return http.HandleConnectionEx(ctx, conn, reader, authenticator, adapter.NewUpstreamHandlerEx(metadata, h.newUserConnection, h.streamUserPacketConnection), metadata.Source, onClose)
	}
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) streamUserPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		if !metadata.Destination.IsValid() {
			h.logger.InfoContext(ctx, "inbound packet connection")
		} else {
			h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
		}
		h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	if !metadata.Destination.IsValid() {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection")
	} else {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
