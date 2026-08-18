package adapter

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
)

type ConnectionManager interface {
	Lifecycle
	Count() int
	CloseAll()
	// ResetHealth — InHive 2026-07-26: хук смены сети (ResetNetwork) для
	// per-outbound health-состояния. С переходом на бюджетную схему дегрейда
	// (2026-08-18) сетепривязанного состояния в нём не осталось и тело
	// пустое, но chokepoint «сеть сменилась» сохранён. Отдельно от CloseAll
	// намеренно: CloseAll зовётся и на закрытии бокса, и юзерской кнопкой
	// «закрыть все соединения» (daemon CloseAllConnections) — там сеть не
	// менялась. См. route/conn.go.
	ResetHealth()
	// IsOutboundDegraded — InHive 2026-08-11: читать пометку дегрейда
	// (серия отказов дайла, бюджет попыток урезан — НЕ «сервер мёртв»)
	// снаружи route. Нужно DNS-клиенту (dns/client.go): дегрейд-контроль
	// прикрывает только app-дайлы (NewConnection), а DNS-путь шёл мимо —
	// даже когда health уже знал, что outbound фейлит, DNS-ждуны стояли по
	// 10s на имя (инцидент 2026-08-10, «cache wait timeout» 1080 из ~2900
	// ошибок). Read-only: состояние здоровья меняют только app-дайлы.
	IsOutboundDegraded(tag string) bool
	TrackConn(conn net.Conn) net.Conn
	TrackPacketConn(conn net.PacketConn) net.PacketConn
	NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
	NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
}
