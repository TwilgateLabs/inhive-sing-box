package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

var _ adapter.ConnectionManager = (*ConnectionManager)(nil)

// maxConcurrentDials — backpressure-cap на число ОДНОВРЕМЕННО блокирующих
// исходящих TCP-dial'ов (P1-a, 2026-07-02). Каждый app-сокет на TUN-пути идёт
// через NewConnection → DialSerialNetwork, который блокируется до
// TCPConnectTimeout (5s), когда upstream мёртв (NL null-route 2026-07-02). Под
// штормом ретраев блокирующие dial'ы копятся, и каждый держит горутину-стек +
// cached-буфер + gVisor-endpoint + (в cgo-резолве/ProtectFunc) OS-тред → это
// phys_footprint ВНЕ Go-heap: SetMemoryLimit его не капит, а iOS jetsam меряет
// именно его против ~50MB NE-бюджета. Слот занимается только на время самого
// dial-вызова (не на всё соединение); на насыщении flow дропается — тем же
// приёмом, что DNS-обмен выше своего cap (route/dns.go). 256 — щедрый потолок
// на одного клиента, тюнится по on-device repro.
const maxConcurrentDials = 256

var (
	dialSem        = make(chan struct{}, maxConcurrentDials)
	dialsDropped   atomic.Uint64
	dialLastLogSec atomic.Int64
)

// tryAcquireDial занимает слот без блокировки. true — слот занят (вызывающий
// обязан вызвать releaseDial по завершении dial). false — насыщение, flow надо
// дропнуть.
func tryAcquireDial() bool {
	select {
	case dialSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseDial() { <-dialSem }

// Дегрейд-контроль per-outbound (2026-07-17, переработан 2026-08-18). Когда
// активный сервер сдох (NL null-route хостера — рецидивирующий blackhole
// play2go), приложения штормят TCP-ретраями: без ограничителя КАЖДЫЙ дайл
// честно висит до TCPConnectTimeout (5s), пиня горутину-стек + cached-буфер +
// gVisor-endpoint + (в cgo ProtectFunc-резолве) OS-тред. Под iOS-лимитом
// SetMaxThreads(512) это → `fatal error: thread exhaustion` = SIGABRT (краш
// мака 2026-07-02/17), а footprint вне Go-heap → jetsam на телефоне. dial-cap
// 256 ограничивает ОДНОВРЕМЕННОСТЬ, но шторм не гасит (256 висящих × 5s
// бесконечно). Эта защита ресурсов — обязательная, не опциональная.
//
// Первая версия (2026-07-17..2026-08-18) была классическим circuit-breaker'ом:
// 8 подряд-фейлов → ЗАПОМНЕННЫЙ вердикт «сервер мёртв» (down), все дайлы
// fast-fail, кроме одного probe раз в backoff-интервал (1s→30s). Замеры с mac
// TestFlight (2026-08-18): 11 trip'ов за 5 дней, длительности до 56s при
// реальных сбоях сети в секунды, 4429 fast-fail'ов — после потолка backoff'а
// между probe проходило 30s, и всё это время НИ ОДНА попытка не шла. Юзер
// видел «засор»: интернет как будто есть, а труба стоит, пока запрос случайно
// не попадёт в окно probe. Корень: механизм смешал (1) защиту ресурсов и
// (2) запомненный вердикт; задержка восстановления — свойство вердикта
// (кто-то должен сходить его раз-помнить), а не сети.
//
// Теперь дегрейд — не ОТКАЗ, а ПОНИЖЕННЫЙ БЮДЖЕТ попыток: после порога
// подряд-фейлов outbound получает лимит одновременных блокирующих дайлов
// (degradedDialBudget). Есть свободный слот → дайл идёт полным путём с
// обычным таймаутом; слотов нет → shed. Отсев — по НАСЫЩЕНИЮ ПРЯМО СЕЙЧАС,
// а не по флагу «мы решили, что он мёртв». Это самолечится: когда сервер
// оживает, одна из висящих попыток отвечает через RTT, успех снимает дегрейд
// мгновенно. Probe/backoff не нужны — восстановление ловят реальные дайлы,
// которые всегда в полёте. Защита ресурсов сохранена: на больной outbound
// висит не больше degradedDialBudget дайлов.
//
// Сознательно НЕ делаем (чтобы не переизобрели):
//   - НЕ сжимаем таймаут дайла под наблюдаемый RTT. Скорость восстановления
//     определяется тем, что попытки постоянно в полёте, а не длиной таймаута.
//     Плюс сжатие требовало бы ctx-дедлайна, а отмена производного ctx после
//     успешного дайла может рвать установленные соединения у протоколов,
//     держащих ctx-привязанные горутины (mux/quic/hysteria). Не лезем.
//   - НЕ подавляем дегрейд, когда direct тоже падает («виновата локальная
//     сеть, сервер ни при чём»): при мёртвом Wi-Fi падает ВСЁ, и подавление
//     вернуло бы ровно шторм 2026-07-17 — полный таймаут × полная
//     одновременность на слабой сети = thread exhaustion. При бюджетной схеме
//     ложный дегрейд стоит копейки (урезанный бюджет на ~RTT), усложнение не
//     окупается.
//   - Туннель по-прежнему НЕ переключает сервер сам (решение Никиты
//     2026-07-17: остаёмся на выбранном сервере — юзер сам пингует и меняет
//     конфиг, авто-подмена врёт о сервере). Никакого авто-failover.
type outboundHealth struct {
	consecFails   atomic.Int64 // подряд-фейлов дайла до дегрейда (сброс на успех)
	degraded      atomic.Bool  // true = серия отказов, бюджет дайлов урезан (НЕ «сервер мёртв»)
	degradedSince atomic.Int64 // unixNano входа в дегрейд (для лога recovery «сколько был degraded»)
	inFlight      atomic.Int64 // блокирующие дайлы этого outbound'а в полёте (бюджетный счётчик)
}

// Наблюдаемость (2026-08-11). В диагностике инцидента 2026-08-10 было НОЛЬ
// следов брейкера при явном dial-шторме (dropped 12→47, goroutines 89→340):
// и брейкер, и dial-cap закрывают через CloseOnHandshakeFailure, чья ошибка
// никуда не логируется — по логам нельзя было отличить «не сработал» от
// «сработал и не помогло» (класс unreportable-bug: механизм безопасности
// невидим). Логируем ПЕРЕХОДЫ (degraded/recovered — редкие по построению),
// а shed'ы — rate-limited счётчиком раз в секунду, тем же приёмом, что
// dial-cap (dialLastLogSec + CompareAndSwap). Уровень WARN: дефолтный log
// level клиента — 'warn' (singbox_config_builder), INFO/DEBUG до box.log
// не доехали бы.
var (
	cbShedDials  atomic.Uint64
	cbShedLogSec atomic.Int64
)

const (
	// cbFailThreshold — подряд-фейлов дайла до входа в дегрейд. Это не
	// «диагноз серверу», а просто сигнал «пора урезать бюджет попыток».
	cbFailThreshold = 8

	// degradedDialBudget — потолок одновременных блокирующих дайлов
	// degraded-outbound'а. Почему 32 против потолков системы: iOS governor
	// SetMaxThreads(512) — жёсткая смерть (SIGABRT); глобальный dialSem = 256;
	// DNS-путь ест ещё до 96 своих слотов (route/dns.go). 32 висящих дайла
	// пинят ≤32 OS-тредов (~6% от 512) — даже несколько одновременно
	// degraded outbound'ов вместе с DNS-cap'ом далеки от потолка тредов, и
	// 224 слота глобального dialSem остаются живым outbound'ам. При этом 32
	// попытки × 5s TCPConnectTimeout под app-штормом означают, что попытки
	// в полёте практически непрерывно — оживший сервер детектится за ~RTT,
	// а не за окно probe. Меньше (например 8) — жальче для реального
	// юзерского трафика в транзиентный сбой; больше — теряется смысл
	// урезания. Тюнится по on-device замерам.
	degradedDialBudget = 32
)

// tryAcquireSlot занимает слот бюджета дайлов outbound'а. inFlight считается
// ВСЕГДА (не только в дегрейде): дайлы, повисшие ещё до входа в дегрейд, тоже
// пинят треды и обязаны учитываться в бюджете — иначе trip при 256 висящих
// пустил бы поверх ещё 32. Отсев только в дегрейде и только при насыщении.
// false → flow надо shed'нуть. Вынесено в метод ради юнит-теста
// (conn_test.go): тест обязан гонять ТУ ЖЕ логику, а не её копию.
func (h *outboundHealth) tryAcquireSlot() bool {
	if h.inFlight.Add(1) > degradedDialBudget && h.degraded.Load() {
		h.inFlight.Add(-1)
		return false
	}
	return true
}

// releaseSlot возвращает слот бюджета. Обязан вызываться ровно один раз на
// каждый успешный tryAcquireSlot, на ВСЕХ путях выхода — утёкший слот не
// самоисцеляется, и outbound залипнет в shed навсегда.
func (h *outboundHealth) releaseSlot() { h.inFlight.Add(-1) }

type ConnectionManager struct {
	logger      logger.ContextLogger
	access      sync.Mutex
	connections list.List[io.Closer]
	health      sync.Map // outboundTag(string) -> *outboundHealth
}

func NewConnectionManager(logger logger.ContextLogger) *ConnectionManager {
	return &ConnectionManager{
		logger: logger,
	}
}

// outboundHealthFor возвращает (создавая при первом обращении) health-состояние
// outbound'а по тегу.
func (m *ConnectionManager) outboundHealthFor(tag string) *outboundHealth {
	if v, ok := m.health.Load(tag); ok {
		return v.(*outboundHealth)
	}
	v, _ := m.health.LoadOrStore(tag, &outboundHealth{})
	return v.(*outboundHealth)
}

// IsOutboundDegraded — read-only доступ к пометке degraded для не-dial путей
// (adapter.ConnectionManager). Сейчас единственный потребитель — DNS-клиент:
// fast-fail запросов через transport, чей detour-outbound в дегрейде,
// вместо 10s ожидания на имя (инцидент 2026-08-10). Нарочно НЕ создаёт
// health-запись: отсутствие записи = «не degraded».
func (m *ConnectionManager) IsOutboundDegraded(tag string) bool {
	if v, ok := m.health.Load(tag); ok {
		return v.(*outboundHealth).degraded.Load()
	}
	return false
}

func (m *ConnectionManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *ConnectionManager) Count() int {
	return m.connections.Len()
}

// ResetHealth — хук смены сети (зовётся из NetworkManager.ResetNetwork рядом
// с CloseAll: смена интерфейса, resume Windows, wake-reset iOS после долгого
// сна). Исторически сбрасывал probe-часы circuit-breaker'а: без сброса
// сервер, помеченный down на старом Wi-Fi, fast-fail'ил дайлы на новой,
// рабочей сети до 30с (потолок probe-backoff'а). С переходом на бюджетную
// схему (2026-08-18) probe-часов больше нет, а дайлы degraded-outbound'а
// и так идут полным путём (до degradedDialBudget одновременных) — первая же
// попытка на новой сети проверяет сервер сама, сбрасывать нечего.
//
// degraded/consecFails НЕ сбрасываем — это решение, не забывчивость. При
// ФЛАПЕ интерфейса (дрожащий Wi-Fi даёт ResetNetwork каждые несколько
// секунд) счётчик обнулялся бы раньше, чем добирался до порога 8, дегрейд
// не наступал бы НИКОГДА — и возвращается шторм висящих дайлов ровно в
// сценарии слабой сети на iOS, где он убивает процесс (thread exhaustion,
// 2026-07-17). Цена сохранения при бюджетной схеме мизерна: ложный дегрейд
// живёт до первого успешного дайла (~RTT), а не до окна probe. Гейт:
// conn_test.go assert'ит сохранение. inFlight не трогаем тем более — он
// привязан к реально висящим дайлам, а не к сети.
//
// Метод оставлен в интерфейсе (adapter.ConnectionManager) с пустым телом:
// вызов из ResetNetwork — осмысленный chokepoint «сеть сменилась», и если
// сетепривязанное состояние здесь снова появится, чистить его надо будет
// именно тут.
//
// Смежное per-outbound состояние, ОСОЗНАННО не сбрасываемое здесь: DNS
// negFail-кэш (dns/client.go) — TTL 5с, самоистекает быстрее, чем юзер
// заметит; urltest-история (UI-вердикты пингов) — обновляется только явным
// пингом по решению Никиты, к маршрутизации трафика не привязана.
func (m *ConnectionManager) ResetHealth() {}

func (m *ConnectionManager) CloseAll() {
	m.access.Lock()
	var closers []io.Closer
	for element := m.connections.Front(); element != nil; {
		nextElement := element.Next()
		closers = append(closers, element.Value)
		m.connections.Remove(element)
		element = nextElement
	}
	m.access.Unlock()
	for _, closer := range closers {
		common.Close(closer)
	}
}

func (m *ConnectionManager) Close() error {
	m.CloseAll()
	return nil
}

func (m *ConnectionManager) TrackConn(conn net.Conn) net.Conn {
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	return &trackedConn{
		Conn:    conn,
		manager: m,
		element: element,
	}
}

func (m *ConnectionManager) TrackPacketConn(conn net.PacketConn) net.PacketConn {
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	return &trackedPacketConn{
		PacketConn: conn,
		manager:    m,
		element:    element,
	}
}

func (m *ConnectionManager) NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	// Дегрейд-контроль (2026-07-17, бюджетная схема 2026-08-18): дайл
	// конкурирует за per-outbound бюджет одновременных блокирующих дайлов.
	// Вне дегрейда бюджет не ограничивает (капит глобальный dialSem); в
	// дегрейде насыщение бюджета → shed. Проверка ДО dial-cap — shed'нутые
	// дайлы не касаются глобального семафора, его слоты остаются живым
	// outbound'ам. См. комментарий у outboundHealth.
	var (
		health    *outboundHealth
		healthTag string
	)
	if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
		healthTag = outbound.Tag()
		health = m.outboundHealthFor(healthTag)
		if !health.tryAcquireSlot() {
			// Rate-limited (≤1 строка/с) счётчик shed'ов — по образцу dial-cap
			// ниже. Каждый дайл логировать нельзя: в шторме их тысячи/с.
			shed := cbShedDials.Add(1)
			now := time.Now().Unix()
			last := cbShedLogSec.Load()
			if now != last && cbShedLogSec.CompareAndSwap(last, now) {
				m.logger.WarnContext(ctx, "outbound [", healthTag, "] degraded: dial budget saturated, shed ", shed, " dials total")
			}
			N.CloseOnHandshakeFailure(conn, onClose, E.New("outbound [", healthTag, "] degraded, dial budget saturated"))
			return
		}
	}
	// P1-a (2026-07-02): cap на одновременные блокирующие исходящие dial'ы.
	// На насыщении дропаем flow (не копим заблокированные горутины/треды/буферы),
	// с rate-limited логом — тем же приёмом, что DNS-обмен на udpnat-пути.
	if !tryAcquireDial() {
		// Слот бюджета взят, а глобального слота нет — вернуть, иначе бюджет
		// утечёт и outbound залипнет в shed навсегда.
		if health != nil {
			health.releaseSlot()
		}
		dropped := dialsDropped.Add(1)
		now := time.Now().Unix()
		last := dialLastLogSec.Load()
		if now != last && dialLastLogSec.CompareAndSwap(last, now) {
			m.logger.WarnContext(ctx, "outbound dials overloaded, dropped ", dropped, " connections")
		}
		N.CloseOnHandshakeFailure(conn, onClose, E.New("outbound dials overloaded"))
		return
	}
	var (
		remoteConn net.Conn
		err        error
	)
	if len(metadata.DestinationAddresses) > 0 || metadata.Destination.IsIP() {
		remoteConn, err = dialer.DialSerialNetwork(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
	} else {
		remoteConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	}
	// Слоты (глобальный и бюджетный) держим только на время самого
	// блокирующего dial — соединение уже установлено (или упало), дальше
	// копи-горутины тред не держат.
	releaseDial()
	if health != nil {
		health.releaseSlot()
		// Обновляем здоровье outbound'а по исходу дайла. Отмена по ctx
		// (юзер закрыл сокет) здоровьем не считается.
		m.updateHealthAfterDial(ctx, health, healthTag, err)
	}
	if err != nil {
		var remoteString string
		if len(metadata.DestinationAddresses) > 0 {
			remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
		} else {
			remoteString = metadata.Destination.String()
		}
		var dialerString string
		if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
			dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			if outbound.Type() == C.TypeBalancer {
				dialerString += "[" + metadata.GetRealOutbound() + "]"
			}
		}
		err = E.Cause(err, "open connection to ", remoteString, dialerString)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	err = N.ReportConnHandshakeSuccess(conn, remoteConn)
	if err != nil {
		err = E.Cause(err, "report handshake success")
		remoteConn.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	if metadata.TLSFragment || metadata.TLSRecordFragment {
		remoteConn = tf.NewConn(remoteConn, ctx, metadata.TLSFragment, metadata.TLSRecordFragment, metadata.TLSFragmentFallbackDelay)
	}
	var done atomic.Bool
	m.preConnectionCopy(ctx, conn, remoteConn, false, &done, onClose)
	m.preConnectionCopy(ctx, remoteConn, conn, true, &done, onClose)
	go m.connectionCopy(ctx, conn, remoteConn, false, &done, onClose)
	go m.connectionCopy(ctx, remoteConn, conn, true, &done, onClose)
}

// updateHealthAfterDial — переходы состояния дегрейда по исходу дайла.
// Вынесено из NewConnection ради юнит-теста (conn_test.go): тест обязан
// проверять ТУ ЖЕ логику переходов и логирования, а не её копию. Логируются
// только ПЕРЕХОДЫ (degraded / recovered) — они редкие по построению, в
// отличие от самих дайлов; см. комментарий у cbShedDials.
func (m *ConnectionManager) updateHealthAfterDial(ctx context.Context, health *outboundHealth, tag string, err error) {
	switch {
	case err == nil:
		// Успех → сервер жив/ожил, полный сброс. Дегрейд снимается МГНОВЕННО
		// первым же успешным дайлом — никакого probe-окна ждать не нужно,
		// попытки и так постоянно в полёте (в этом весь смысл бюджетной
		// схемы). Swap вместо Store: ловим переход true→false ровно один раз
		// для лога.
		health.consecFails.Store(0)
		if health.degraded.Swap(false) {
			m.logger.WarnContext(ctx, "outbound [", tag, "] recovered after ",
				time.Duration(time.Now().UnixNano()-health.degradedSince.Load()).Round(time.Second), " degraded")
		}
	case errors.Is(err, context.Canceled):
		// отмена юзером — не сигнал здоровья, игнор
	default:
		// dial-фейл (timeout/refused) → счётчик; порог → дегрейд: урезать
		// бюджет одновременных попыток. Это НЕ вердикт «сервер мёртв» —
		// дайлы продолжают идти (до degradedDialBudget одновременных).
		// CompareAndSwap вместо Load+Store: переход false→true клеймится
		// ровно одним дайлом — degradedSince/лог не перетираются конкурентом.
		fails := health.consecFails.Add(1)
		if fails >= cbFailThreshold && health.degraded.CompareAndSwap(false, true) {
			health.degradedSince.Store(time.Now().UnixNano())
			m.logger.WarnContext(ctx, "outbound [", tag, "] degraded after ", fails,
				" consecutive dial failures (concurrent dial budget capped at ", degradedDialBudget, ")")
		}
	}
}

func (m *ConnectionManager) NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remotePacketConn   net.PacketConn
		remoteConn         net.Conn
		destinationAddress netip.Addr
		err                error
	)
	if metadata.UDPConnect {
		parallelDialer, isParallelDialer := this.(dialer.ParallelInterfaceDialer)
		if len(metadata.DestinationAddresses) > 0 {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = N.DialSerial(ctx, this, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses)
			}
		} else if metadata.Destination.IsIP() {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
			}
		} else {
			remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
		}
		if err != nil {
			var remoteString string
			if len(metadata.DestinationAddresses) > 0 {
				remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
			} else {
				remoteString = metadata.Destination.String()
			}
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
				if outbound.Type() == C.TypeBalancer {
					dialerString += "[" + metadata.GetRealOutbound() + "]"
				}
			}
			err = E.Cause(err, "open packet connection to ", remoteString, dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
		remotePacketConn = bufio.NewUnbindPacketConn(remoteConn)
		connRemoteAddr := M.AddrFromNet(remoteConn.RemoteAddr())
		if connRemoteAddr != metadata.Destination.Addr {
			destinationAddress = connRemoteAddr
		}
	} else {
		if len(metadata.DestinationAddresses) > 0 {
			remotePacketConn, destinationAddress, err = dialer.ListenSerialNetworkPacket(ctx, this, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
		} else if packetDialer, withDestination := this.(dialer.PacketDialerWithDestination); withDestination {
			remotePacketConn, destinationAddress, err = packetDialer.ListenPacketWithDestination(ctx, metadata.Destination)
		} else {
			remotePacketConn, err = this.ListenPacket(ctx, metadata.Destination)
		}
		if err != nil {
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
				if outbound.Type() == C.TypeBalancer {
					dialerString += "[" + metadata.GetRealOutbound() + "]"
				}
			}
			err = E.Cause(err, "listen packet connection using ", dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
	}
	err = N.ReportPacketConnHandshakeSuccess(conn, remotePacketConn)
	if err != nil {
		conn.Close()
		remotePacketConn.Close()
		m.logger.ErrorContext(ctx, "report handshake success: ", err)
		return
	}
	if destinationAddress.IsValid() {
		var originDestination M.Socksaddr
		if metadata.RouteOriginalDestination.IsValid() {
			originDestination = metadata.RouteOriginalDestination
		} else {
			originDestination = metadata.Destination
		}
		if natConn, loaded := common.Cast[bufio.NATPacketConn](conn); loaded {
			natConn.UpdateDestination(destinationAddress)
		} else {
			destination := M.SocksaddrFrom(destinationAddress, metadata.Destination.Port)
			if metadata.Destination != destination {
				if metadata.UDPDisableDomainUnmapping {
					remotePacketConn = bufio.NewUnidirectionalNATPacketConn(bufio.NewPacketConn(remotePacketConn), destination, originDestination)
				} else {
					remotePacketConn = bufio.NewNATPacketConn(bufio.NewPacketConn(remotePacketConn), destination, originDestination)
				}
			} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
				remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
			}
		}
	} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
		remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
	}
	var udpTimeout time.Duration
	if metadata.UDPTimeout > 0 {
		udpTimeout = metadata.UDPTimeout
	} else {
		protocol := metadata.Protocol
		if protocol == "" {
			protocol = C.PortProtocols[metadata.Destination.Port]
		}
		if protocol != "" {
			udpTimeout = C.ProtocolTimeouts[protocol]
		}
	}
	if udpTimeout > 0 {
		ctx, conn = canceler.NewPacketConn(ctx, conn, udpTimeout)
	}
	destination := bufio.NewPacketConn(remotePacketConn)
	var done atomic.Bool
	go m.packetConnectionCopy(ctx, conn, destination, false, &done, onClose)
	go m.packetConnectionCopy(ctx, destination, conn, true, &done, onClose)
}

func (m *ConnectionManager) preConnectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	readHandshake := N.NeedHandshakeForRead(source)
	writeHandshake := N.NeedHandshakeForWrite(destination)
	if readHandshake || writeHandshake {
		var err error
		for {
			err = m.connectionCopyEarlyWrite(source, destination, readHandshake, writeHandshake)
			if err == nil && N.NeedHandshakeForRead(source) {
				continue
			} else if isBenignPreConnError(err) {
				// inhive: fast-path замена E.IsMulti (reflection). На hot path
				// одно TCP соединение = один этот вызов, errors.As жрал ~10% CPU.
				err = nil
			}
			break
		}
		if err != nil {
			if done.Swap(true) {
				if onClose != nil {
					onClose(err)
				}
			}
			common.Close(source, destination)
			if !direction {
				m.logger.ErrorContext(ctx, "connection upload handshake: ", err)
			} else {
				m.logger.ErrorContext(ctx, "connection download handshake: ", err)
			}
			return
		}
	}
}

func (m *ConnectionManager) connectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	var (
		sourceReader      io.Reader = source
		destinationWriter io.Writer = destination
	)
	var readCounters, writeCounters []N.CountFunc
	for {
		sourceReader, readCounters = N.UnwrapCountReader(sourceReader, readCounters)
		destinationWriter, writeCounters = N.UnwrapCountWriter(destinationWriter, writeCounters)
		if cachedSrc, isCached := sourceReader.(N.CachedReader); isCached {
			cachedBuffer := cachedSrc.ReadCached()
			if cachedBuffer != nil {
				dataLen := cachedBuffer.Len()
				_, err := destination.Write(cachedBuffer.Bytes())
				cachedBuffer.Release()
				if err != nil {
					if done.Swap(true) {
						if onClose != nil {
							onClose(err)
						}
					}
					common.Close(source, destination)
					if !direction {
						m.logger.ErrorContext(ctx, "connection upload payload: ", err)
					} else {
						m.logger.ErrorContext(ctx, "connection download payload: ", err)
					}
					return
				}
				for _, counter := range readCounters {
					counter(int64(dataLen))
				}
				for _, counter := range writeCounters {
					counter(int64(dataLen))
				}
			}
			continue
		}
		break
	}

	_, err := bufio.CopyWithCounters(destinationWriter, sourceReader, source, readCounters, writeCounters, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	if err != nil {
		common.Close(source, destination)
	} else if duplexDst, isDuplex := destination.(N.WriteCloser); isDuplex {
		err = duplexDst.CloseWrite()
		if err != nil {
			common.Close(source, destination)
		}
	} else {
		destination.Close()
	}
	if done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
		common.Close(source, destination)
	}
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "connection upload finished")
		} else if !E.IsClosedOrCanceled(err) && !strings.Contains(err.Error(), "NO_ERROR") {
			m.logger.ErrorContext(ctx, "connection upload closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection upload closed")
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "connection download finished")
		} else if !E.IsClosedOrCanceled(err) && !strings.Contains(err.Error(), "NO_ERROR") && !strings.Contains(err.Error(), "response body closed") {
			m.logger.ErrorContext(ctx, "connection download closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection download closed")
		}
	}
}

func (m *ConnectionManager) connectionCopyEarlyWrite(source net.Conn, destination io.Writer, readHandshake bool, writeHandshake bool) error {
	payload := buf.NewPacket()
	defer payload.Release()
	err := source.SetReadDeadline(time.Now().Add(C.ReadPayloadTimeout))
	if err != nil {
		if err == os.ErrInvalid {
			if writeHandshake {
				return common.Error(destination.Write(nil))
			}
		}
		return err
	}
	// inhive Fix v3: возвращаем timeout/EOF наружу, НЕ проглатываем.
	// Иначе preConnectionCopy видит err=nil + handshake still pending → hot loop.
	// Upstream sing-box 12b05598 (Fix preConnectionCopy, sekai.icu, 2025-09-14).
	// Регрессия в коммите 80908859 случайно откатила этот fix → 500% CPU burn
	// при failed VLESS handshake (сервер закрыл сокет на partial read).
	var (
		isTimeout bool
		isEOF     bool
	)
	_, err = payload.ReadOnceFrom(source)
	if err != nil {
		if isNetTimeout(err) {
			// inhive: isNetTimeout вместо E.IsTimeout — избегаем errors.As reflection.
			isTimeout = true
		} else if errors.Is(err, io.EOF) {
			isEOF = true
		} else {
			return E.Cause(err, "read payload")
		}
	}
	_ = source.SetReadDeadline(time.Time{})
	if !payload.IsEmpty() || writeHandshake {
		_, err = destination.Write(payload.Bytes())
		if err != nil {
			return E.Cause(err, "write payload")
		}
	}
	if isTimeout {
		return context.DeadlineExceeded
	} else if isEOF {
		return io.EOF
	}
	return nil
}

func (m *ConnectionManager) packetConnectionCopy(ctx context.Context, source N.PacketReader, destination N.PacketWriter, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	// inhive: containment for a racy/nil select fault observed inside
	// sing@v0.8.4 udpnat2.(*natConn).WaitReadPacket (sigpanic 0xc0000005 via
	// runtime.selectgo). A UDP-NAT fault must drop this single packet conn, not
	// crash the whole process + VPN service. Recover converts the fault into a
	// normal closed-conn teardown. Follow-up: confirm the nil channel in
	// udpnat2/conn.go:68 upstream (a sing bump 0.8.4->0.8.9 is WIP/risky).
	defer func() {
		if r := recover(); r != nil {
			// fmt.Sprint: сырое r через format.ToString ре-паникует на
			// не-примитивных panic-значениях — containment ловил бы только
			// «удобные» паники.
			msg := fmt.Sprint(r)
			m.logger.ErrorContext(ctx, "packet connection copy panic recovered: ", msg)
			if !done.Swap(true) {
				if onClose != nil {
					onClose(E.New("packet connection copy panic: ", msg))
				}
			}
			common.Close(source, destination)
		}
	}()
	_, err := bufio.CopyPacket(destination, source)
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "packet upload finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet upload closed")
		} else {
			m.logger.DebugContext(ctx, "packet upload closed: ", err)
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "packet download finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet download closed")
		} else {
			m.logger.DebugContext(ctx, "packet download closed: ", err)
		}
	}
	if !done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
	}
	common.Close(source, destination)
}

type trackedConn struct {
	net.Conn
	manager *ConnectionManager
	element *list.Element[io.Closer]
}

func (c *trackedConn) Close() error {
	c.manager.access.Lock()
	c.manager.connections.Remove(c.element)
	c.manager.access.Unlock()
	return c.Conn.Close()
}

func (c *trackedConn) Upstream() any {
	return c.Conn
}

func (c *trackedConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedConn) WriterReplaceable() bool {
	return true
}

type trackedPacketConn struct {
	net.PacketConn
	manager *ConnectionManager
	element *list.Element[io.Closer]
}

func (c *trackedPacketConn) Close() error {
	c.manager.access.Lock()
	c.manager.connections.Remove(c.element)
	c.manager.access.Unlock()
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) Upstream() any {
	return bufio.NewPacketConn(c.PacketConn)
}

func (c *trackedPacketConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedPacketConn) WriterReplaceable() bool {
	return true
}

// isNetTimeout — zero-reflection timeout check. Ручной walk Unwrap chain
// с type switch. Прошлая версия через err.(interface{Timeout() bool}) не
// ловила wrapped *net.OpError (inbound источник завёрнут через trackedConn
// и bufio layers), и fallback errors.As возвращал 12s CPU (17% cum по pprof).
// Теперь цепочку разворачиваем вручную — выявленно через профайль HOT_061047.
func isNetTimeout(err error) bool {
	for cur := err; cur != nil; {
		switch e := cur.(type) {
		case *net.OpError:
			return e.Timeout()
		case interface{ Timeout() bool }:
			return e.Timeout()
		case interface{ Unwrap() error }:
			cur = e.Unwrap()
			continue
		case interface{ Unwrap() []error }:
			for _, sub := range e.Unwrap() {
				if isNetTimeout(sub) {
					return true
				}
			}
			return false
		}
		break
	}
	return false
}

// isBenignPreConnError — zero-reflection проверка benign error sentinels.
// Вместо errors.Is (который тоже проходит через Unwrap с interface dispatch)
// раскручиваем вручную и сравниваем по значению.
func isBenignPreConnError(err error) bool {
	for cur := err; cur != nil; {
		if cur == os.ErrInvalid || cur == context.DeadlineExceeded || cur == io.EOF {
			return true
		}
		// Пробуем метод Is() если есть (net.errDeadlineExceeded implements Is).
		if ie, ok := cur.(interface{ Is(error) bool }); ok {
			if ie.Is(os.ErrInvalid) || ie.Is(context.DeadlineExceeded) || ie.Is(io.EOF) {
				return true
			}
		}
		if u, ok := cur.(interface{ Unwrap() error }); ok {
			cur = u.Unwrap()
			continue
		}
		break
	}
	return false
}
