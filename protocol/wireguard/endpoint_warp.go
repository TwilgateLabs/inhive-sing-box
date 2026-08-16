package wireguard

import (
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterWARPEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WireGuardWARPEndpointOptions](registry, C.TypeWARP, NewWARPEndpoint)
}

type WARPEndpoint struct {
	endpoint.Adapter
	endpoint     adapter.Endpoint
	startHandler func()

	mtx sync.Mutex
}

func NewWARPEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardWARPEndpointOptions) (adapter.Endpoint, error) {
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	warpEndpoint := &WARPEndpoint{
		Adapter: endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
	}
	uniqueId := options.UniqueIdentifier
	if uniqueId == "" {
		uniqueId = tag
	}
	warpEndpoint.mtx.Lock()
	warpEndpoint.startHandler = func() {
		defer warpEndpoint.mtx.Unlock()
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var config *C.WARPConfig
		var err error
		if !options.Profile.Recreate && cacheFile != nil && cacheFile.StoreWARPConfig() {
			savedProfile := cacheFile.LoadBinary(uniqueId)
			if savedProfile != nil {
				// A cache entry that does not unmarshal or does not validate is
				// treated as NO cache (fetch a fresh profile below), not as a fatal
				// error and certainly not as input for the construction code — a
				// stale/partial cached config used to panic at config.Peers[0]
				// inside this goroutine and kill the whole process.
				if err = json.Unmarshal(savedProfile.Content, &config); err != nil {
					logger.ErrorContext(ctx, E.Cause(err, "broken cached WARP config, refetching"))
					config = nil
				} else if err = validateWARPConfig(config); err != nil {
					logger.ErrorContext(ctx, E.Cause(err, "invalid cached WARP config, refetching"))
					config = nil
				}
			}
		}
		if config == nil && options.WARPConfig != nil {
			config = options.WARPConfig
		}
		if config == nil || config.PrivateKey == "" {
			profile, err := GetWarpProfile(ctx, &options.Profile)
			if err != nil {
				logger.ErrorContext(ctx, err)
				return
			}
			config = &profile.Config

			if cacheFile != nil && cacheFile.StoreWARPConfig() {
				content, err := json.Marshal(config)
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
				cacheFile.SaveBinary(uniqueId, &adapter.SavedBinary{
					LastUpdated: time.Now(),
					Content:     content,
					LastEtag:    "",
				})
			}
		}
		// startHandler runs in its own goroutine (Start does `go w.startHandler()`),
		// so ANY panic here is an unrecoverable process-killing crash, not an error
		// the user ever sees. validateWARPConfig above guarantees Peers is non-empty
		// and the interface addresses parse; pickWARPPeerPort guarantees the port
		// selection cannot hit rand.Intn(0).
		if err := validateWARPConfig(config); err != nil {
			logger.ErrorContext(ctx, E.Cause(err, "invalid WARP config"))
			return
		}
		peer := config.Peers[0]
		hostParts := strings.Split(peer.Endpoint.Host, ":")
		peerAddr := hostParts[0]
		perrPort := pickWARPPeerPort(options.ServerOptions.ServerPort, peer.Endpoint.Ports, hostParts)
		if options.ServerOptions.Server != "" {
			peerAddr = options.ServerOptions.Server
		}
		warpEndpoint.endpoint, err = NewEndpoint(
			ctx,
			router,
			logger,
			tag,
			option.WireGuardEndpointOptions{
				System:                     options.System,
				Name:                       options.Name,
				ListenPort:                 options.ListenPort,
				UDPTimeout:                 options.UDPTimeout,
				Workers:                    options.Workers,
				PreallocatedBuffersPerPool: options.PreallocatedBuffersPerPool,
				DisablePauses:              options.DisablePauses,
				Noise:                      options.Noise,
				DialerOptions:              options.DialerOptions,

				Address: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix(config.Interface.Addresses.V4 + "/32"),
					netip.MustParsePrefix(config.Interface.Addresses.V6 + "/128"),
				},
				PrivateKey: config.PrivateKey,
				Peers: []option.WireGuardPeer{
					{
						Address:   peerAddr,
						Port:      perrPort,
						PublicKey: peer.PublicKey,
						AllowedIPs: badoption.Listable[netip.Prefix]{
							netip.MustParsePrefix("0.0.0.0/0"),
							netip.MustParsePrefix("::/0"),
						},
					},
				},
				MTU: options.MTU,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		if err = warpEndpoint.endpoint.Start(adapter.StartStateStart); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		if err = warpEndpoint.endpoint.Start(adapter.StartStatePostStart); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
	}
	return warpEndpoint, nil
}

// validateWARPConfig rejects every WARPConfig shape that used to panic inside
// the startHandler goroutine and therefore kill the whole process:
//   - empty Peers        → config.Peers[0] index out of range
//   - bad/empty addresses → netip.MustParsePrefix panic
//
// (empty Ports — rand.Intn(0) — is handled separately by pickWARPPeerPort,
// because a port can still legitimately come from the Host or an override.)
func validateWARPConfig(config *C.WARPConfig) error {
	if config == nil {
		return E.New("missing config")
	}
	if config.PrivateKey == "" {
		return E.New("missing private_key")
	}
	if len(config.Peers) == 0 {
		return E.New("missing peers")
	}
	if config.Peers[0].PublicKey == "" {
		return E.New("missing peer public_key")
	}
	if _, err := netip.ParsePrefix(config.Interface.Addresses.V4 + "/32"); err != nil {
		return E.Cause(err, "invalid interface v4 address")
	}
	if _, err := netip.ParsePrefix(config.Interface.Addresses.V6 + "/128"); err != nil {
		return E.Cause(err, "invalid interface v6 address")
	}
	return nil
}

// pickWARPPeerPort never panics: the old inline rand.Intn(len(ports)) crashed
// the process when a cached or user-supplied config carried an empty ports
// list. Priority: explicit override > advertised ports > port embedded in the
// endpoint host ("engage.cloudflareclient.com:2408") > Cloudflare's default.
func pickWARPPeerPort(override uint16, ports []int, hostParts []string) uint16 {
	if override != 0 {
		return override
	}
	if len(ports) > 0 {
		return uint16(ports[rand.Intn(len(ports))])
	}
	if len(hostParts) > 1 {
		if port, err := strconv.ParseUint(hostParts[1], 10, 16); err == nil && port != 0 {
			return uint16(port)
		}
	}
	return 2408 // default WARP UDP port
}
func GetWarpProfile(ctx context.Context, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	var dialer N.Dialer
	outmanager := service.FromContext[adapter.OutboundManager](ctx)
	if profile.Detour != "" && outmanager != nil {
		var ok bool
		dialer, ok = outmanager.Outbound(profile.Detour)
		if !ok {
			return nil, E.New("outbound detour not found: ", profile.Detour)
		}

	}
	cf, err := GetWarpProfileDialer(ctx, dialer, profile)
	if err == nil || outmanager == nil {
		return cf, nil
	}

	for _, dialer := range outmanager.Outbounds() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if cf, err := GetWarpProfileDialer(ctx, dialer, profile); err == nil {
			return cf, nil
		}
	}
	return nil, err

}
func GetWarpProfileDialer(ctx context.Context, dialer N.Dialer, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	api := cloudflare.NewCloudflareApiDetour(dialer)
	if profile.AuthToken != "" && profile.ID != "" {
		return api.GetProfile(ctx, profile.AuthToken, profile.ID)

	} else {
		return api.CreateProfileLicense(ctx, profile.PrivateKey, profile.License)
	}
}
func (w *WARPEndpoint) IsReady() bool {
	if ok := w.isEndpointInitialized(); !ok {
		return false
	}
	return w.endpoint.IsReady()
}
func (w *WARPEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	go w.startHandler()
	return nil
}

func (w *WARPEndpoint) Close() error {
	return common.Close(w.endpoint)
}

func (w *WARPEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if ok := w.isEndpointInitialized(); !ok {
		return nil, E.New("endpoint not initialized")
	}
	return w.endpoint.DialContext(ctx, network, destination)
}

func (w *WARPEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if ok := w.isEndpointInitialized(); !ok {
		return nil, E.New("endpoint not initialized")
	}
	return w.endpoint.ListenPacket(ctx, destination)
}

func (w *WARPEndpoint) isEndpointInitialized() bool {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return w.endpoint != nil
}

func (w *WARPEndpoint) DisplayType() string {
	str := C.ProxyDisplayName(w.Type())
	if !w.IsReady() {
		str += " ⚠️ Connecting..."
	}
	return str
}
