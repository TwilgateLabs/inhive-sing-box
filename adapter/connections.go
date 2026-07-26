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
	// ResetHealth — InHive 2026-07-26: забыть probe-часы circuit-breaker'а
	// после смены сети (ResetNetwork), НЕ снимая пометку down. Отдельно от
	// CloseAll намеренно: CloseAll зовётся и на закрытии бокса, и юзерской
	// кнопкой «закрыть все соединения» (daemon CloseAllConnections) — там
	// сеть не менялась и забывать здоровье неправильно. См. route/conn.go.
	ResetHealth()
	TrackConn(conn net.Conn) net.Conn
	TrackPacketConn(conn net.PacketConn) net.PacketConn
	NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
	NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
}
