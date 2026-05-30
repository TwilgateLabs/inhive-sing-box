package outbound

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	logger                  log.ContextLogger
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	started                 bool
	stage                   adapter.StartStage
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	dependByTag             map[string][]string
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
}

func NewManager(logger logger.ContextLogger, registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		logger:        logger,
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
		dependByTag:   make(map[string][]string),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	if stage == adapter.StartStateStart {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
		outbounds := m.outbounds
		m.access.Unlock()
		return m.startOutbounds(append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
	} else {
		outbounds := m.outbounds
		m.access.Unlock()
		for _, outbound := range outbounds {
			name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			m.logger.Trace(stage, " ", name)
			startTime := time.Now()
			err := adapter.LegacyStart(outbound, stage)
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
			m.logger.Trace(stage, " ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
		}
	}
	return nil
}

func (m *Manager) startOutbounds(outbounds []adapter.Outbound) error {
	monitor := taskmonitor.New(m.logger, C.StartTimeout)
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
			if starter, isStarter := outboundToStart.(adapter.Lifecycle); isStarter {
				m.logger.Trace("start ", name)
				startTime := time.Now()
				monitor.Start("start ", name)
				err := starter.Start(adapter.StartStateStart)
				monitor.Finish()
				if err != nil {
					return E.Cause(err, "start ", name)
				}
				m.logger.Trace("start ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
			} else if starter, isStarter := outboundToStart.(interface {
				Start() error
			}); isStarter {
				m.logger.Trace("start ", name)
				startTime := time.Now()
				monitor.Start("start ", name)
				err := starter.Start()
				monitor.Finish()
				if err != nil {
					return E.Cause(err, "start ", name)
				}
				m.logger.Trace("start ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
			}
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			m.access.Lock()
			problemOutbound := m.outboundByTag[problemOutboundTag]
			m.access.Unlock()
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return nil
}

// Close tears down every outbound. InHive note: an outbound's Close() has no
// context/deadline (io.Closer), so a wedged one — e.g. a WebRTC/olcrtc
// outbound stuck draining a peer connection — used to block the whole serial
// loop. That stalled box teardown -> CoreService.Stop held static.lock -> the
// gRPC/Mobile Stop never returned -> on iOS the kernel TUN stayed up while
// traffic poured into a dead tunnel. So we bound the *entire* teardown to a
// single overall budget (C.StopTimeout) rather than per-outbound: per-outbound
// would allow N wedged outbounds to cost N*StopTimeout, which is exactly the
// hang we are fixing. Healthy outbounds (milliseconds) still run effectively
// in order; once the shared budget is exhausted, any remaining Close() calls
// are fired-and-forgotten so the loop returns immediately. An abandoned
// goroutine may leak, which is an acceptable trade for guaranteeing Stop()
// releases the lock and the tunnel is torn down. Protocol-agnostic: this
// protects Reality / UTProto / Naive / olcrtc identically.
func (m *Manager) Close() error {
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	m.access.Lock()
	if !m.started {
		m.access.Unlock()
		return nil
	}
	m.started = false
	outbounds := m.outbounds
	m.outbounds = nil
	m.access.Unlock()
	deadline := time.Now().Add(C.StopTimeout)
	var err error
	for _, outbound := range outbounds {
		closer, isCloser := outbound.(io.Closer)
		if !isCloser {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		// Run every Close() in its own goroutine so a wedged outbound can be
		// abandoned. done carries the (possibly nil) close error.
		done := make(chan error, 1)
		go func() {
			done <- closer.Close()
		}()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Shared teardown budget already spent: do not wait. Abandon the
			// in-flight Close() (its goroutine drains into the buffered chan)
			// and move on so Stop() can return.
			m.logger.Warn("close ", name, " abandoned: teardown budget exhausted")
			continue
		}

		m.logger.Trace("close ", name)
		startTime := time.Now()
		monitor.Start("close ", name)
		select {
		case closeErr := <-done:
			monitor.Finish()
			err = E.Append(err, closeErr, func(err error) error {
				return E.Cause(err, "close ", name)
			})
			m.logger.Trace("close ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
		case <-time.After(remaining):
			monitor.Finish()
			// This outbound wedged. Abandon its goroutine (leak accepted),
			// log which one, and keep going — the shared deadline is now
			// effectively expired, so subsequent outbounds take the fast path.
			m.logger.Warn("close ", name, " timed out after ", F.Seconds(time.Since(startTime).Seconds()), "s, abandoning")
		}
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.outbounds
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	defer m.access.Unlock()
	outbound, found := m.outboundByTag[tag]
	if !found {
		return os.ErrInvalid
	}
	delete(m.outboundByTag, tag)
	index := common.Index(m.outbounds, func(it adapter.Outbound) bool {
		return it == outbound
	})
	if index == -1 {
		panic("invalid inbound index")
	}
	m.outbounds = append(m.outbounds[:index], m.outbounds[index+1:]...)
	started := m.started
	if m.defaultOutbound == outbound {
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
			m.logger.Info("updated default outbound to ", m.defaultOutbound.Tag())
		} else {
			m.defaultOutbound = nil
		}
	}
	dependBy := m.dependByTag[tag]
	if len(dependBy) > 0 {
		return E.New("outbound[", tag, "] is depended by ", strings.Join(dependBy, ", "))
	}
	dependencies := outbound.Dependencies()
	for _, dependency := range dependencies {
		if len(m.dependByTag[dependency]) == 1 {
			delete(m.dependByTag, dependency)
		} else {
			m.dependByTag[dependency] = common.Filter(m.dependByTag[dependency], func(it string) bool {
				return it != tag
			})
		}
	}
	if started {
		return common.Close(outbound)
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil { // InHive: fallback to invalid config вместо жёсткого fail
		err2 := E.New("parse outbound[", tag, "] error: ", err)
		m.logger.Error(err2)
		outbound, err = m.registry.CreateOutbound(ctx, router, logger, tag, C.TypeInvalidConfig, &option.InvalidOptions{
			InvalidConfig: options,
			Err:           err2,
		})
		if err != nil {
			return err
		}
	}

	if m.started {
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			m.logger.Trace(stage, " ", name)
			startTime := time.Now()
			err = adapter.LegacyStart(outbound, stage)
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
			m.logger.Trace(stage, " ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
		}
	}
	m.access.Lock()
	defer m.access.Unlock()
	if existsOutbound, loaded := m.outboundByTag[tag]; loaded {
		if m.started {
			err = common.Close(existsOutbound)
			if err != nil {
				return E.Cause(err, "close outbound/", existsOutbound.Type(), "[", existsOutbound.Tag(), "]")
			}
		}
		existsIndex := common.Index(m.outbounds, func(it adapter.Outbound) bool {
			return it == existsOutbound
		})
		if existsIndex == -1 {
			panic("invalid inbound index")
		}
		m.outbounds = append(m.outbounds[:existsIndex], m.outbounds[existsIndex+1:]...)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	dependencies := outbound.Dependencies()
	for _, dependency := range dependencies {
		m.dependByTag[dependency] = append(m.dependByTag[dependency], tag)
	}
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
		if m.started {
			m.logger.Info("updated default outbound to ", outbound.Tag())
		}
	}
	return nil
}
