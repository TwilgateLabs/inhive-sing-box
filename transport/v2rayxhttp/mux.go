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
	// InHive 2026-07-29 (фикс зомби-xmux, кандидат в PR к XTLS/Xray-core — у
	// апстрима та же утечка: prune в GetHTTPClient выкидывает клиента без Close).
	//
	// inflightPosts — число upload-POST'ов (packet-up), находящихся в полёте на
	// этом клиенте. OpenUsage его НЕ покрывает: цикл отправки в DialContext
	// РОТИРУЕТ клиента (c.getHTTPClient() при исчерпании LeftRequests /
	// UnreusableAt), и ротационные клиенты в OpenUsage не считаются — у Xray это
	// не важно, он никогда не закрывает, а нам нельзя закрыть транспорт под
	// летящим POST'ом (обрыв POST = Interrupt всей upload-половины сессии).
	inflightPosts atomic.Int32
	// handedOutAt — момент последней выдачи клиента из GetXmuxClient (запись и
	// чтение под m.mtx). Между возвратом из GetXmuxClient и OpenUsage.Add(1) /
	// inflightPosts.Add(1) у вызывающего есть окно, где клиент уже выдан, но по
	// счётчикам выглядит свободным — закрывать его в этом окне нельзя (гонка
	// «выдан, но ещё не посчитан»), поэтому закрытие гейтится grace-паузой от
	// последней выдачи (см. idleLocked).
	handedOutAt time.Time
	// closePlanned — закрытие уже запланировано (под m.mtx); страховка от
	// двойного Close поверх структурного инварианта «закрываемый клиент
	// удаляется из xmuxClients/retired».
	closePlanned bool
}

type XmuxManager struct {
	options     option.V2RayXHTTPXmuxOptions
	concurrency int32
	connections int32
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	// InHive 2026-07-29: «пенсионеры» — клиенты, выкинутые prune'ом из пула, но
	// ещё удерживаемые живыми стримами (OpenUsage>0: download-GET packet-up живёт
	// всю жизнь проксируемого conn — часы/сутки у push-соединений) или летящими
	// POST'ами (inflightPosts>0). Закрывать их сразу нельзя — in-flight стримы
	// легитимны; раньше они просто исчезали из учёта БЕЗ Close и навсегда
	// удерживали свой http2.Transport + горутины + uTLS-буферы (device-снимок
	// 255ч: connsCreated=70, live≤6, goroutines ~2x baseline). Теперь их
	// подметает sweepRetiredLocked, как только счётчики падают до нуля.
	retired []*XmuxClient
	mtx     sync.Mutex
}

// xmuxHandoutCloseGrace — минимальная пауза после последней выдачи клиента,
// раньше которой prune/sweep не имеют права его закрыть. Закрывает гонку
// «GetXmuxClient вернул клиента, а OpenUsage.Add(1) в DialContext ещё не
// выполнился» (окно — микросекунды; 5с — с огромным запасом). var, а не const —
// чтобы тесты могли ужать паузу.
var xmuxHandoutCloseGrace = 5 * time.Second

// idleLocked — можно ли закрывать клиента ПРЯМО СЕЙЧАС (вызывать под m.mtx).
func (c *XmuxClient) idleLocked(now time.Time) bool {
	return !c.closePlanned &&
		c.OpenUsage.Load() == 0 &&
		c.inflightPosts.Load() == 0 &&
		now.Sub(c.handedOutAt) >= xmuxHandoutCloseGrace
}

// closeXmuxClients закрывает XmuxConn'ы СПИСКОМ и ВНЕ лока менеджера: Close у
// DefaultDialerClient рвёт реальные TCP/QUIC-сессии (может блокироваться), под
// m.mtx ему делать нечего. Список собирается под локом (с выставленным
// closePlanned), закрывается после разблокировки.
func closeXmuxClients(clients []*XmuxClient) {
	for _, xmuxClient := range clients {
		if closer, ok := xmuxClient.XmuxConn.(io.Closer); ok {
			_ = closer.Close()
		}
	}
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
	// Свежесозданный клиент тут же выдаётся вызывающему — фиксируем выдачу, иначе
	// при cMaxReuseTimes=1 (leftUsage сразу 0) конкурентный GetXmuxClient мог бы
	// закрыть его до того, как вызывающий успел инкрементировать OpenUsage.
	xmuxClient.handedOutAt = time.Now()
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
	toClose := make([]*XmuxClient, 0, len(m.xmuxClients)+len(m.retired))
	toClose = append(toClose, m.xmuxClients...)
	// InHive 2026-07-29: retired-хвост закрывается тем же сбросом — Reset значит
	// «сеть сменилась/конфиг перезапущен», in-flight стримы на этих соединениях
	// уже мертвы или бессмысленны, ждать их нечего.
	toClose = append(toClose, m.retired...)
	for _, xmuxClient := range toClose {
		xmuxClient.closePlanned = true
	}
	m.xmuxClients = make([]*XmuxClient, 0)
	recordXmuxRetired(-len(m.retired))
	m.retired = nil
	m.mtx.Unlock()
	// Close вне лока: рвёт реальные соединения, может блокироваться.
	closeXmuxClients(toClose)
}

// SweepRetired подметает retired-хвост: закрывает клиентов, у которых больше
// нет ни открытых стримов, ни летящих POST'ов. Дёргается из onClose
// проксируемого conn (client.go) — закрытие conn'а и есть тот момент, когда
// пенсионер, которого он удерживал, становится свободным; плюс на каждом
// GetXmuxClient (страховка на случай, если onClose-путь не сработал).
func (m *XmuxManager) SweepRetired() {
	m.mtx.Lock()
	toClose := m.sweepRetiredLocked(time.Now())
	m.mtx.Unlock()
	if len(toClose) > 0 {
		closeXmuxClients(toClose)
		recordXmuxReaped(len(toClose))
	}
}

// sweepRetiredLocked — вызывать под m.mtx; возвращает клиентов, которых надо
// закрыть ПОСЛЕ разблокировки. Занятых (OpenUsage/inflightPosts > 0) не трогает.
func (m *XmuxManager) sweepRetiredLocked(now time.Time) []*XmuxClient {
	var toClose []*XmuxClient
	for i := 0; i < len(m.retired); {
		xmuxClient := m.retired[i]
		if xmuxClient.idleLocked(now) {
			xmuxClient.closePlanned = true
			m.retired = append(m.retired[:i], m.retired[i+1:]...)
			recordXmuxRetired(-1)
			toClose = append(toClose, xmuxClient)
		} else {
			i++
		}
	}
	return toClose
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient {
	m.mtx.Lock()
	xmuxClient, toClose := m.getXmuxClientLocked()
	m.mtx.Unlock()
	// Close вне лока (см. closeXmuxClients).
	if len(toClose) > 0 {
		closeXmuxClients(toClose)
		recordXmuxReaped(len(toClose))
	}
	return xmuxClient
}

func (m *XmuxManager) getXmuxClientLocked() (*XmuxClient, []*XmuxClient) {
	now := time.Now()
	var toClose []*XmuxClient
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		if xmuxClient.XmuxConn.IsClosed() ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && now.After(xmuxClient.UnreusableAt)) {
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
			// InHive 2026-07-29, фикс утечки зомби-соединений (upstream-баг Xray,
			// кандидат в PR к XTLS: их GetHTTPClient делает тот же prune без Close).
			// Раньше пруненный клиент просто исчезал из учёта: его http2.Transport,
			// горутины и uTLS-буферы жили, пока их держал хоть один стрим (download-GET
			// packet-up живёт всю жизнь проксируемого conn — у push-соединений
			// часы/сутки), а после — до idle-таймера, которого при активном стриме не
			// бывает. За 255ч аптайма копился хвост из десятков таких зомби (~6-15MB
			// + 2x горутин). Теперь: свободного закрываем сразу, занятого — в retired
			// до момента, когда его отпустит последний стрим/POST (сразу закрывать
			// нельзя: in-flight стримы легитимны, ровно поэтому Xray и не закрывает).
			// Ветка IsClosed() тоже проходит через Close: флаг closed выставляется и
			// по ошибке запроса (dialer.go PostPacket/OpenStream) БЕЗ закрытия
			// транспорта — такому клиенту Close нужен не меньше, чем протухшему.
			if xmuxClient.idleLocked(now) {
				xmuxClient.closePlanned = true
				toClose = append(toClose, xmuxClient)
			} else {
				m.retired = append(m.retired, xmuxClient)
				recordXmuxRetired(1)
			}
		} else {
			i++
		}
	}
	toClose = append(toClose, m.sweepRetiredLocked(now)...)
	// InHive instrumentation (TEMPORARY, see chunkhist.go): pool size AFTER the
	// prune above, i.e. how many live connections we actually keep around.
	recordXmuxPool(len(m.xmuxClients))
	if len(m.xmuxClients) == 0 {
		return m.newXmuxClient(), toClose
	}
	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		return m.newXmuxClient(), toClose
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
		return m.newXmuxClient(), toClose
	}
	i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(xmuxClients))))
	xmuxClient := xmuxClients[i.Int64()]
	if xmuxClient.leftUsage > 0 {
		xmuxClient.leftUsage -= 1
	}
	// Фиксация выдачи — гейт от закрытия в окне «выдан, но ещё не посчитан».
	xmuxClient.handedOutAt = now
	return xmuxClient, toClose
}

// connProber — DialerClient, умеющий проверить свой h2-пул (DefaultDialerClient).
type connProber interface {
	ProbeConns(ctx context.Context, timeout time.Duration) (probed int, closed int)
}

// Probe — InHive 2026-09-08: проверка ВСЕХ клиентов пула (активных и retired)
// PING'ом по каждому их h2-соединению; закрываются только не ответившие.
// Снимок списка — под m.mtx, проверки — параллельно и вне лока (проба длится
// до timeout, держать под ней менеджер нельзя: GetXmuxClient встанет).
// Замена Reset() для wake-пути: Reset рвёт и занятые соединения, Probe — нет.
func (m *XmuxManager) Probe(ctx context.Context, timeout time.Duration) (probed int, closed int) {
	m.mtx.Lock()
	clients := make([]*XmuxClient, 0, len(m.xmuxClients)+len(m.retired))
	clients = append(clients, m.xmuxClients...)
	clients = append(clients, m.retired...)
	m.mtx.Unlock()
	var (
		wg     sync.WaitGroup
		sumMtx sync.Mutex
	)
	for _, xmuxClient := range clients {
		prober, ok := xmuxClient.XmuxConn.(connProber)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(prober connProber) {
			defer wg.Done()
			p, c := prober.ProbeConns(ctx, timeout)
			sumMtx.Lock()
			probed += p
			closed += c
			sumMtx.Unlock()
		}(prober)
	}
	wg.Wait()
	return probed, closed
}
