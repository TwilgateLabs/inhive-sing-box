package adapter

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
)

type V2RayServerTransport interface {
	Network() []string
	Serve(listener net.Listener) error
	ServePacket(listener net.PacketConn) error
	Close() error
}

type V2RayServerTransportHandler interface {
	N.TCPConnectionHandlerEx
}

type V2RayClientTransport interface {
	DialContext(ctx context.Context) (net.Conn, error)
	Close() error
}

// SleepProber — InHive 2026-09-08. Outbound/транспорт, умеющий ПРОВЕРИТЬ свои
// пулы долгоживущих соединений после сна девайса, а не сбросить их вслепую.
// Контракт: закрывать ТОЛЬКО те соединения, которые не ответили на проверку;
// живые (в т.ч. занятые стримами) не трогать. Возвращает число проверенных и
// число закрытых. Дёргается из hcore.Wake() (v2/hcore/pause.go) под гейтом
// «процесс был заморожен ≥ N» — см. там, почему именно так.
type SleepProber interface {
	ProbeAfterSleep(ctx context.Context) (probed int, closed int)
}
