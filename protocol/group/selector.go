package group

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.OutboundGroup             = (*Selector)(nil)
	_ adapter.ConnectionHandlerEx       = (*Selector)(nil)
	_ adapter.PacketConnectionHandlerEx = (*Selector)(nil)
)

type Selector struct {
	outbound.Adapter
	ctx        context.Context
	outbound   adapter.OutboundManager
	connection adapter.ConnectionManager
	logger     logger.ContextLogger
	// InHive hot-add (2026-07-19): membership мутируется в рантайме
	// (AddMember/RemoveMember из hcore AddOutbound/RemoveOutbound RPC), поэтому
	// tags/outbounds под RWMutex. Upstream снапшотил их один раз в Start() и
	// читал без лока. Горячий путь (DialContext/NewConnectionEx) не страдает —
	// он ходит только в атомарный selected.
	access                       sync.RWMutex
	tags                         []string
	defaultTag                   string
	outbounds                    map[string]adapter.Outbound
	selected                     common.TypedValue[adapter.Outbound]
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	outbound := &Selector{
		Adapter:                      outbound.NewAdapter(C.TypeSelector, tag, nil, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		defaultTag:                   options.Default,
		outbounds:                    make(map[string]adapter.Outbound),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start() error {
	s.access.Lock()
	defer s.access.Unlock()
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = detour
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			selected := cacheFile.LoadSelected(s.Tag())
			if selected != "" {
				detour, loaded := s.outbounds[selected]
				if loaded {
					s.selected.Store(detour)
					return nil
				}
			}
		}
	}

	if s.defaultTag != "" {
		detour, loaded := s.outbounds[s.defaultTag]
		if !loaded {
			return E.New("default outbound not found: ", s.defaultTag)
		}
		s.selected.Store(detour)
		return nil
	}

	s.selected.Store(s.outbounds[s.tags[0]])
	return nil
}

func (s *Selector) PostStart() error {
	s.pingSelected()
	return nil
}

func (s *Selector) Now() string {
	selected := s.selected.Load()
	if selected == nil {
		s.access.RLock()
		defer s.access.RUnlock()
		return s.tags[0]
	}
	return selected.Tag()
}

func (s *Selector) All() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	// Копия: caller'ы (clash API getProxies) итерируют вне лока.
	return append([]string(nil), s.tags...)
}

// AddMember добавляет outbound в живой селектор (InHive hot-add). Outbound
// обязан быть УЖЕ создан и запущен в OutboundManager (Create с started=true) —
// селектор здесь только регистрирует членство. Повторное добавление тега
// обновляет резолв (семантика replace — как у manager.Create).
func (s *Selector) AddMember(tag string, detour adapter.Outbound) {
	s.access.Lock()
	defer s.access.Unlock()
	if _, exists := s.outbounds[tag]; !exists {
		s.tags = append(s.tags, tag)
	}
	s.outbounds[tag] = detour
}

// RemoveMember убирает outbound из членов селектора. Если удаляемый был
// выбран — выбор переводится на defaultTag (или первый член), активные
// соединения interrupt'ятся. Сам outbound из OutboundManager НЕ удаляется —
// это ответственность вызывающего (hcore RemoveOutbound: сначала членства,
// потом manager.Remove, иначе dangling-указатель из selected).
func (s *Selector) RemoveMember(tag string) bool {
	s.access.Lock()
	removed, exists := s.outbounds[tag]
	if !exists {
		s.access.Unlock()
		return false
	}
	delete(s.outbounds, tag)
	for i, t := range s.tags {
		if t == tag {
			s.tags = append(s.tags[:i], s.tags[i+1:]...)
			break
		}
	}
	var fallback adapter.Outbound
	if s.selected.Load() == removed {
		if d, ok := s.outbounds[s.defaultTag]; ok {
			fallback = d
		} else if len(s.tags) > 0 {
			fallback = s.outbounds[s.tags[0]]
		}
	}
	s.access.Unlock()
	if fallback != nil {
		s.selected.Store(fallback)
		s.interruptGroup.Interrupt(true)
	}
	return true
}

func (s *Selector) SelectOutbound(tag string) bool {
	defer s.pingSelected()
	s.access.RLock()
	detour, loaded := s.outbounds[tag]
	s.access.RUnlock()
	if !loaded {
		return false
	}

	if s.selected.Swap(detour) == detour {
		return true
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			err := cacheFile.StoreSelected(s.Tag(), tag)
			if err != nil {
				s.logger.Error("store selected: ", err)
			}
		}
	}

	s.interruptGroup.Interrupt(s.interruptExternalConnections)
	return true
}
func (s *Selector) pingSelected() {
	selected := s.selected.Load()
	if selected == nil {
		s.logger.Warn("no outbound selected")
		return
	}
	realTag := RealTag(selected)
	// s.logger.Debug("pinging selected outbound: ", selected.Tag(), " (real tag: ", realTag, ")")
	if r, ok := s.outbound.Outbound(realTag); ok {
		// s.logger.Debug("found real tag: ", selected.Tag(), " (real tag: ", r.Tag(), ")")
		if _, ok := r.(adapter.OutboundGroup); !ok {
			monitoring.Get(s.ctx).TestNow(realTag)
		} else {
			// s.logger.Debug(" real tag: is a group so skipping ping", selected.Tag(), " (real tag: ", r.Tag(), ")")
			monitoring.Get(s.ctx).SignalChange(s.Tag())
		}
	}
}
func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.selected.Load().DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := s.selected.Load().ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	conn = s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx))
	if outboundHandler, isHandler := selected.(adapter.ConnectionHandlerEx); isHandler {
		outboundHandler.NewConnectionEx(ctx, conn, metadata, onClose)
	} else {
		s.connection.NewConnection(ctx, selected, conn, metadata, onClose)
	}
}

func (s *Selector) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	conn = s.interruptGroup.NewSingPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx))
	if outboundHandler, isHandler := selected.(adapter.PacketConnectionHandlerEx); isHandler {
		outboundHandler.NewPacketConnectionEx(ctx, conn, metadata, onClose)
	} else {
		s.connection.NewPacketConnection(ctx, selected, conn, metadata, onClose)
	}
}

func (s *Selector) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	selected := s.selected.Load()
	if !common.Contains(selected.Network(), metadata.Network) {
		return nil, E.New(metadata.Network, " is not supported by outbound: ", selected.Tag())
	}
	return selected.(adapter.DirectRouteOutbound).NewDirectRouteConnection(metadata, routeContext, timeout)
}

func RealTag(detour adapter.Outbound) string {
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		return group.Now()
	}
	return detour.Tag()
}
