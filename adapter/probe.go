package adapter

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

// ProbeFreshDialer — opt-in способность outbound'а выполнить ОДНУ пробу
// достижимости через СВЕЖИЙ транспорт, минуя переиспользуемый пул/сессию.
//
// Зачем (InHive, 2026-07-22). Пулящиеся протоколы держат живое верхнеуровневое
// соединение и переиспользуют его в обычном DialContext:
//   - sing-mux — mux-сессия;
//   - xhttp/splithttp — xmux h2/h3-клиент (наш порт Xray splithttp);
//   - hysteria2 / tuic — QUIC-сессия.
// urltest через такой пул после смены оператора/сети получает ЛОЖНЫЙ зелёный:
// протухшая-но-ещё-живая сессия отвечает на пробу, хотя НОВОЕ соединение сейчас
// не встаёт. DialProbeFresh обязан поднять транзиентную сессию (свой underlying
// dial + свой хендшейк), вернуть по ней conn и закрыть эту сессию вместе с
// conn'ом.
//
// Контракт:
//   - боевой пул outbound'а НЕ трогать: не закрывать и не ресетить существующие
//     соединения/сессии (защита архитектурная, не полагается на клиента);
//   - ровно ОДНА свежая сессия на пробу, закрывается по Close() возвращённого
//     conn'а;
//   - без глобальных локов и без Manager.Create/Remove (ровно они повесили
//     clash API в клон-варианте 146).
//
// Реализуют ТОЛЬКО пулящиеся протоколы. Плоские (plain vless/trojan/reality,
// utproto FakeTLS, direct) интерфейс НЕ реализуют — их обычный DialContext уже
// открывает свежий underlying-conn + свежий хендшейк, поэтому urltest для них
// падает обратно на DialContext (естественный no-op).
type ProbeFreshDialer interface {
	DialProbeFresh(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

// ProbeConn оборачивает conn пробы так, что его Close() дополнительно закрывает
// транзиентную сессию/клиент, созданные ТОЛЬКО ради этой пробы. Используется
// протоколами, чей fresh-дайл поднимает отдельный клиент (hysteria2/tuic).
type ProbeConn struct {
	net.Conn
	OnClose func() error
}

func (c *ProbeConn) Close() error {
	err := c.Conn.Close()
	if c.OnClose != nil {
		if cerr := c.OnClose(); err == nil {
			err = cerr
		}
	}
	return err
}
