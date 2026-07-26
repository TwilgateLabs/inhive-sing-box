package route

import (
	"context"
	"errors"
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

// Circuit-breaker per-outbound (2026-07-17). Когда активный сервер сдох (NL
// null-route хостера — рецидивирующий blackhole play2go), приложения штормят
// TCP-ретраями: без брейкера КАЖДЫЙ дайл честно висит до TCPConnectTimeout (5s),
// пиня горутину-стек + cached-буфер + gVisor-endpoint + (в cgo ProtectFunc-
// резолве) OS-тред. Под iOS-лимитом SetMaxThreads(512) это → `fatal error:
// thread exhaustion` = SIGABRT (краш мака 2026-07-02/17), а footprint вне
// Go-heap → jetsam на телефоне. dial-cap 256 ограничивает ОДНОВРЕМЕННОСТЬ, но
// шторм не гасит (256 висящих × 5s бесконечно). Брейкер помечает outbound down
// после N подряд-фейлов и fast-fail'ит его дайлы МГНОВЕННО (0ms, слот/тред не
// занимаются), пропуская 1 probe/с для детекта оживления. Туннель НЕ
// переключается и НЕ реконнектится (решение Никиты: остаёмся на выбранном
// сервере — юзер сам пингует и меняет конфиг, авто-подмена врёт о сервере).
// Сервер self-heal (15-20 мин) → probe ловит → трафик идёт на ТОМ ЖЕ сервере.
type outboundHealth struct {
	consecFails   atomic.Int64 // подряд-фейлов дайла до trip (сброс на успех)
	down          atomic.Bool  // true = outbound помечен мёртвым
	lastProbe     atomic.Int64 // unixNano последнего probe-дайла
	probeInterval atomic.Int64 // текущий backoff-интервал probe (наносек)
}

const (
	cbFailThreshold = 8                // подряд-фейлов → trip (пометить down)
	cbProbeBase     = time.Second      // стартовый интервал probe после trip
	cbProbeMax      = 30 * time.Second // потолок backoff'а (=макс время между проверками recovery)
)

// tryClaimProbe — атомарно решает, идёт ли этот дайл down-outbound'а полным
// путём как probe (не чаще раза в probeInterval; 0 трактуется как cbProbeBase —
// свежий trip и сброс ResetHealth дают немедленный probe). Вынесено из
// NewConnection единственно ради юнит-теста (conn_test.go): тест обязан
// проверять ТУ ЖЕ логику, а не её копию — иначе связанность-на-расстоянии.
func (h *outboundHealth) tryClaimProbe(nowNano int64) bool {
	last := h.lastProbe.Load()
	interval := h.probeInterval.Load()
	if interval == 0 {
		interval = int64(cbProbeBase)
	}
	return nowNano-last >= interval && h.lastProbe.CompareAndSwap(last, nowNano)
}

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
// брейкера для outbound'а по тегу.
func (m *ConnectionManager) outboundHealthFor(tag string) *outboundHealth {
	if v, ok := m.health.Load(tag); ok {
		return v.(*outboundHealth)
	}
	v, _ := m.health.LoadOrStore(tag, &outboundHealth{})
	return v.(*outboundHealth)
}

func (m *ConnectionManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *ConnectionManager) Count() int {
	return m.connections.Len()
}

// ResetHealth — сброс probe-часов circuit-breaker'а при смене сети (зовётся
// из NetworkManager.ResetNetwork рядом с CloseAll: смена интерфейса, resume
// Windows, wake-reset iOS после долгого сна).
//
// ЗАЧЕМ. Здоровье outbound'а меряется НА КОНКРЕТНОЙ СЕТИ: 8 подряд-фейлов на
// умершем Wi-Fi ничего не говорят о доступности сервера с LTE. Без сброса
// сервер, помеченный down на старой сети, продолжал fast-fail'ить все дайлы
// на новой, рабочей — до 30с (потолок probe-backoff'а): «переключил сеть, а
// VPN ещё полминуты не работает».
//
// Пометку down НЕ снимаем НАМЕРЕННО — её снимает только фактический успешный
// дайл (см. NewConnection). Авто-снятие вернуло бы ровно тот шторм, ради
// которого брейкер строился (8 висящих дайлов × 5с TCPConnectTimeout ×
// каждый down-outbound), и противоречило бы решению Никиты 2026-07-17: сервер
// не подменяем и «здоровым» его не объявляем — это делает только реальность.
// Сбрасываем только probe-часы: probeInterval → 0 (в NewConnection это
// трактуется как cbProbeBase) и lastProbe → 0 — ПЕРВЫЙ ЖЕ дайл на новой сети
// идёт полным путём как probe. Цена: один полный дайл (≤5с TCPConnectTimeout)
// на каждый down-outbound на смену сети; остальные дайлы down-сервера
// по-прежнему fast-fail, шторм не возвращается.
//
// consecFails ТОЖЕ сохраняем — это решение, не забывчивость. Цена сохранения
// мала: 7 фейлов со старого Wi-Fi + один транзиентный фейл на свежей LTE —
// и живой сервер на ~1с ложно down (probe через cbProbeBase тут же снимет).
// Цена сброса — катастрофа в худшем сценарии: при ФЛАПЕ интерфейса
// (дрожащий Wi-Fi даёт ResetNetwork каждые несколько секунд) счётчик
// обнулялся бы раньше, чем добирался до порога 8, брейкер не срабатывал бы
// НИКОГДА — и возвращается шторм висящих дайлов, ради которого он написан,
// ровно в сценарии слабой сети на iOS, где тот убивает процесс (thread
// exhaustion, инцидент 2026-07-17). Асимметрия односторонняя: секунда
// ложного fast-fail против SIGABRT. Гейт: conn_test.go assert'ит сохранение.
//
// Смежное per-outbound состояние, ОСОЗНАННО не сбрасываемое здесь: DNS
// negFail-кэш (dns/client.go) — TTL 5с, самоистекает быстрее, чем юзер
// заметит; urltest-история (UI-вердикты пингов) — обновляется только явным
// пингом по решению Никиты, к маршрутизации трафика не привязана.
func (m *ConnectionManager) ResetHealth() {
	m.health.Range(func(_, value any) bool {
		health := value.(*outboundHealth)
		health.probeInterval.Store(0)
		health.lastProbe.Store(0)
		return true
	})
}

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
	// Circuit-breaker (2026-07-17): достаём health активного outbound'а и, если
	// он помечен down, fast-fail'им дайл МГНОВЕННО (кроме ≤1 probe/с). Проверка
	// ДО dial-cap — fast-fail'ные дайлы не касаются семафора, слоты остаются
	// свободны для probe и дайлов на живые серверы. См. outboundHealth.
	var health *outboundHealth
	var isProbe bool
	if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
		health = m.outboundHealthFor(outbound.Tag())
		if health.down.Load() {
			// Recovery ловится ТОЛЬКО пропущенным probe: пропускаем 1 дайл раз в
			// interval (растёт с backoff'ом), остальные fast-fail (0ms). Никакого
			// синтетического трафика — это одна из уже идущих попыток приложений.
			if health.tryClaimProbe(time.Now().UnixNano()) {
				isProbe = true // идёт полным путём; успех снимет down, фейл увеличит backoff
			} else {
				N.CloseOnHandshakeFailure(conn, onClose, E.New("outbound [", outbound.Tag(), "] circuit-open (server unreachable)"))
				return
			}
		}
	}
	// P1-a (2026-07-02): cap на одновременные блокирующие исходящие dial'ы.
	// На насыщении дропаем flow (не копим заблокированные горутины/треды/буферы),
	// с rate-limited логом — тем же приёмом, что DNS-обмен на udpnat-пути.
	if !tryAcquireDial() {
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
	// Слот держим только на время самого блокирующего dial — соединение уже
	// установлено (или упало), дальше копи-горутины тред не держат.
	releaseDial()
	// Circuit-breaker: обновляем здоровье outbound'а по исходу дайла. Отмена по
	// ctx (юзер закрыл сокет) здоровьем не считается.
	if health != nil {
		switch {
		case err == nil:
			// Успех (обычный дайл или probe) → сервер жив/ожил, полный сброс.
			health.consecFails.Store(0)
			health.probeInterval.Store(0)
			health.down.Store(false)
		case errors.Is(err, context.Canceled):
			// отмена юзером — не сигнал здоровья, игнор
		case isProbe:
			// probe упал — сервер всё ещё мёртв, backoff (×2, потолок cbProbeMax).
			next := health.probeInterval.Load() * 2
			if next < int64(cbProbeBase) {
				next = int64(cbProbeBase)
			}
			if next > int64(cbProbeMax) {
				next = int64(cbProbeMax)
			}
			health.probeInterval.Store(next)
		default:
			// обычный dial-фейл (timeout/refused) на живом-считающемся outbound →
			// счётчик; порог → trip: пометить down, стартовать probe-часы.
			if health.consecFails.Add(1) >= cbFailThreshold && !health.down.Load() {
				health.probeInterval.Store(int64(cbProbeBase))
				health.lastProbe.Store(time.Now().UnixNano())
				health.down.Store(true)
			}
		}
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
			m.logger.ErrorContext(ctx, "packet connection copy panic recovered: ", r)
			if !done.Swap(true) {
				if onClose != nil {
					onClose(E.New("packet connection copy panic: ", r))
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
