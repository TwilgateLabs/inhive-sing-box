package route

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"

	mDNS "github.com/miekg/dns"
)

// maxConcurrentDNSExchange — backpressure-cap на число одновременно живущих
// горутин DNS-обмена на udpnat-hijack пути. На каждый DNS-пакет здесь
// спавнится горутина, и каждая держит живым 8K буфер + распарсенный
// mDNS.Msg. Когда upstream-DNS лежит (как в инциденте 2026-06-25, сервер
// отдавал refused ~8ч), горутины копятся быстрее, чем дренируются → стеки +
// retained буферы лезут к iOS memory-limit → GC death-spiral. 96 — щедрый
// потолок для одного клиента; режет только реальный флуд (это и есть цель).
// Тюнится по on-device QPS.
const maxConcurrentDNSExchange = 96

// dnsExchangeSem — counting-семафор (слот занимается ДО go, освобождается
// внутри горутины по завершении). dnsExchangeDropped — atomic-счётчик
// сброшенных под насыщением пакетов (для rate-limited лога, чтобы сам лог
// не стал источником флуда).
var (
	dnsExchangeSem        = make(chan struct{}, maxConcurrentDNSExchange)
	dnsExchangeDropped    atomic.Uint64
	dnsExchangeLastLogSec atomic.Int64
)

// dnsErrLastLogSec / dnsErrSuppressed — rate-limit для лога ошибок обмена
// ("process DNS packet"). В инциденте 2026-06-25 эта строка спамилась 2760×
// (битые DNS-пакеты при лежащем upstream), жгла string-аллокации + синхронные
// записи в горячем пути — это само по себе топливо к memory-limit. Тот же
// приём, что у dnsExchangeLastLogSec выше: не чаще раза в секунду, с хвостом
// "(+N suppressed)". Счётчик atomic, сбрасывается при каждой реальной записи.
var (
	dnsErrLastLogSec atomic.Int64
	dnsErrSuppressed atomic.Uint64
)

// tryAcquireDNSExchange пытается занять слот семафора без блокировки. true —
// слот занят, вызывающий обязан запустить ExchangeDNSPacket (которая
// освободит слот по defer). false — насыщение: буфер уже освобождён, пакет
// дропнут, инкрементнут drop-счётчик; логируем не чаще раза в секунду.
func tryAcquireDNSExchange(ctx context.Context, logger logger.ContextLogger, buffer *buf.Buffer) bool {
	select {
	case dnsExchangeSem <- struct{}{}:
		return true
	default:
		buffer.Release()
		dropped := dnsExchangeDropped.Add(1)
		now := time.Now().Unix()
		last := dnsExchangeLastLogSec.Load()
		if now != last && dnsExchangeLastLogSec.CompareAndSwap(last, now) {
			logger.WarnContext(ctx, "DNS exchange overloaded, dropped ", dropped, " packets")
		}
		return false
	}
}

func (r *Router) hijackDNSStream(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	metadata.Destination = M.Socksaddr{}
	for {
		conn.SetReadDeadline(time.Now().Add(C.DNSTimeout))
		err := dnsOutbound.HandleStreamDNSRequest(ctx, r.dns, conn, metadata)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				return err
			} else {
				return nil
			}
		}
	}
}

func (r *Router) hijackDNSPacket(ctx context.Context, conn N.PacketConn, packetBuffers []*N.PacketBuffer, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	if natConn, isNatConn := conn.(udpnat.Conn); isNatConn {
		metadata.Destination = M.Socksaddr{}
		for _, packet := range packetBuffers {
			buffer := packet.Buffer
			destination := packet.Destination
			N.PutPacketBuffer(packet)
			// Backpressure-cap: занимаем слот ДО спавна; на насыщении пакет
			// дропается (буфер освобождён внутри tryAcquireDNSExchange).
			if !tryAcquireDNSExchange(ctx, r.logger, buffer) {
				continue
			}
			go ExchangeDNSPacket(ctx, r.dns, r.logger, natConn, buffer, metadata, destination)
		}
		natConn.SetHandler(&dnsHijacker{
			router:   r.dns,
			logger:   r.logger,
			conn:     conn,
			ctx:      ctx,
			metadata: metadata,
			onClose:  onClose,
		})
		return nil
	}
	err := dnsOutbound.NewDNSPacketConnection(ctx, r.dns, conn, packetBuffers, metadata)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil && !E.IsClosedOrCanceled(err) {
		return E.Cause(err, "process DNS packet")
	}
	return nil
}

// ExchangeDNSPacket вызывается ВСЕГДА под уже занятым слотом dnsExchangeSem
// (слот берётся в вызывающем перед go); освобождаем его здесь по завершении.
func ExchangeDNSPacket(ctx context.Context, router adapter.DNSRouter, logger logger.ContextLogger, conn N.PacketConn, buffer *buf.Buffer, metadata adapter.InboundContext, destination M.Socksaddr) {
	defer func() { <-dnsExchangeSem }()
	err := exchangeDNSPacket(ctx, router, conn, buffer, metadata, destination)
	if err != nil && !R.IsRejected(err) && !E.IsClosedOrCanceled(err) {
		logDNSExchangeError(ctx, logger, err)
	}
}

// logDNSExchangeError логирует ошибку обмена DNS-пакетом не чаще раза в
// секунду (rate-limit, см. dnsErrLastLogSec). Подавленные за интервал ошибки
// складываются в хвост "(+N suppressed)", чтобы не терять факт флуда, но и не
// плодить тысячи синхронных записей на битых пакетах.
func logDNSExchangeError(ctx context.Context, logger logger.ContextLogger, err error) {
	now := time.Now().Unix()
	last := dnsErrLastLogSec.Load()
	if now == last || !dnsErrLastLogSec.CompareAndSwap(last, now) {
		dnsErrSuppressed.Add(1)
		return
	}
	if suppressed := dnsErrSuppressed.Swap(0); suppressed > 0 {
		logger.ErrorContext(ctx, E.Cause(err, "process DNS packet"), " (+", suppressed, " suppressed)")
	} else {
		logger.ErrorContext(ctx, E.Cause(err, "process DNS packet"))
	}
}

func exchangeDNSPacket(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, buffer *buf.Buffer, metadata adapter.InboundContext, destination M.Socksaddr) error {
	var message mDNS.Msg
	err := message.Unpack(buffer.Bytes())
	buffer.Release()
	if err != nil {
		return E.Cause(err, "unpack request")
	}
	response, err := router.Exchange(adapter.WithContext(ctx, &metadata), &message, adapter.DNSQueryOptions{})
	if err != nil {
		return err
	}
	responseBuffer, err := dns.TruncateDNSMessage(&message, response, 1024)
	if err != nil {
		return err
	}
	err = conn.WritePacket(responseBuffer, destination)
	return err
}

type dnsHijacker struct {
	router   adapter.DNSRouter
	logger   logger.ContextLogger
	conn     N.PacketConn
	ctx      context.Context
	metadata adapter.InboundContext
	onClose  N.CloseHandlerFunc
}

func (h *dnsHijacker) NewPacketEx(buffer *buf.Buffer, destination M.Socksaddr) {
	// Backpressure-cap: занимаем слот ДО спавна; на насыщении пакет дропается
	// (буфер освобождён внутри tryAcquireDNSExchange).
	if !tryAcquireDNSExchange(h.ctx, h.logger, buffer) {
		return
	}
	go ExchangeDNSPacket(h.ctx, h.router, h.logger, h.conn, buffer, h.metadata, destination)
}

func (h *dnsHijacker) Close() error {
	if h.onClose != nil {
		h.onClose(nil)
	}
	return nil
}
