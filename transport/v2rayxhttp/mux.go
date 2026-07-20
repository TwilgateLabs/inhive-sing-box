package xhttp

import (
	"context"
	"crypto/rand"
	"io"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
)

type XmuxConn interface {
	IsClosed() bool
}

type XmuxClient struct {
	XmuxConn     XmuxConn
	OpenUsage    atomic.Int32
	leftUsage    int32
	LeftRequests atomic.Int32
	UnreusableAt time.Time
}

type XmuxManager struct {
	options     option.V2RayXHTTPXmuxOptions
	concurrency int32
	connections int32
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	mtx         sync.Mutex
}

func NewXmuxManager(options option.V2RayXHTTPXmuxOptions, newConnFunc func() XmuxConn) *XmuxManager {
	m := &XmuxManager{
		options:     options,
		concurrency: options.GetNormalizedMaxConcurrency().Rand(),
		connections: options.GetNormalizedMaxConnections().Rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
	}
	// InHive instrumentation (TEMPORARY, see chunkhist.go).
	recordXmuxConfig(m.concurrency, m.connections)
	return m
}

func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:  m.newConnFunc(),
		leftUsage: -1,
	}
	if x := m.options.GetNormalizedCMaxReuseTimes().Rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.options.GetNormalizedHMaxRequestTimes().Rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	if x := m.options.GetNormalizedHMaxReusableSecs().Rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	// InHive instrumentation (TEMPORARY, see chunkhist.go).
	recordXmuxNewConn(len(m.xmuxClients))
	return xmuxClient
}

// Reset закрывает ВСЕ соединения пула и опустошает его. Менеджер остаётся
// рабочим: следующий GetXmuxClient лениво создаст свежий XmuxConn через
// newConnFunc — это семантика «сброс», не «уничтожение».
//
// InHive 2026-07-19 (в Xray аналога нет — у него другой lifecycle транспорта):
// это опора контракта sing-box V2RayClientTransport.Close(). При событии
// сна/пробуждения Windows route/network.go зовёт ResetNetwork() →
// InterfaceUpdated() у outbound'ов → transport.Close(); без сброса тёплый пул
// xmux (дефолт 26.7.11 — maxConnections 6..6) переживал сброс с мёртвым TCP
// под собой, и туннель после пробуждения висел до аварийных таймеров
// (h2 ReadIdleTimeout 45с + ping 15с, h3 — до 300с). Тот же путь закрывает
// утечку живых H2-сессий при каждом перезапуске конфига (Outbound.Close()).
func (m *XmuxManager) Reset() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for _, xmuxClient := range m.xmuxClients {
		if closer, ok := xmuxClient.XmuxConn.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	m.xmuxClients = make([]*XmuxClient, 0)
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		if xmuxClient.XmuxConn.IsClosed() ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && time.Now().After(xmuxClient.UnreusableAt)) {
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
		} else {
			i++
		}
	}
	// InHive instrumentation (TEMPORARY, see chunkhist.go): pool size AFTER the
	// prune above, i.e. how many live connections we actually keep around.
	recordXmuxPool(len(m.xmuxClients))
	if len(m.xmuxClients) == 0 {
		return m.newXmuxClient()
	}
	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		return m.newXmuxClient()
	}
	xmuxClients := make([]*XmuxClient, 0)
	if m.concurrency > 0 {
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.OpenUsage.Load() < m.concurrency {
				xmuxClients = append(xmuxClients, xmuxClient)
			}
		}
	} else {
		xmuxClients = m.xmuxClients
	}
	if len(xmuxClients) == 0 {
		return m.newXmuxClient()
	}
	i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(xmuxClients))))
	xmuxClient := xmuxClients[i.Int64()]
	if xmuxClient.leftUsage > 0 {
		xmuxClient.leftUsage -= 1
	}
	return xmuxClient
}
