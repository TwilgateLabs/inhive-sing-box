package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/net/http2"
)

var errFallback = E.New("fallback to HTTP/1.1")

// InHive 2026-07-26: h2 health-check для DoH.
//
// Без ReadIdleTimeout мёртвый H2-коннект (девайс поспал ≥30с — NAT/сервер снесли
// TCP, RST нам никто не прислал) не детектится НИКАК: RoundTrip пишет в чёрную
// дыру и живёт до дедлайна запроса. Дедлайн — C.DNSTimeout (10s, dns/client.go
// оборачивает каждый Exchange), т.е. ПЕРВЫЙ DNS-запрос после сна висел все 10s,
// затем negFail-кэш (5s) добивал повторы — поле: 10-20с «интернета нет» после
// пробуждения iPhone (device-лог 2026-07-25).
//
// С health-check'ом: после ≥dohReadIdleTimeout тишины в коннект уходит H2 PING;
// нет ответа за dohPingTimeout — транспорт сам закрывает коннект, in-flight
// стримы падают сразу, следующий запрос идёт по свежему TCP. Сумма
// (5s+4s=9s) ОБЯЗАНА быть < C.DNSTimeout, иначе health-check срабатывает позже
// дедлайна и бесполезен. На живом коннекте с трафиком PING'и не ходят вовсе
// (ReadIdleTimeout меряет тишину по чтению); на молчащем — раз в 5с, это
// browser-уровень фоновой активности (Chrome шлёт h2-PING'и штатно).
//
// dohIdleConnTimeout — цена вопроса в числах. Сам по себе health-check пингует
// молчащий коннект ВЕЧНО (у http2.Transport нет дефолтного idle-timeout), т.е.
// PING раз в 5с всё время, пока поднят туннель: DNS становится самой болтливой
// сущностью в трубе (xhttp пингует раз в 45с, hysteria2 QUIC — раз в 10с). При
// этом коннект, который никому не нужен уже 5 минут, дешевле выбросить, чем
// поддерживать: следующий DNS-запрос заплатит один TLS-хендшейк (~2 RTT), и
// платить его всё равно пришлось бы — после сна девайса коннект мёртв. Плюс
// побочный эффект ровно в масть багу: после долгого сна idle-таймер срабатывает
// на первом же кванте CPU и протухший коннект выбрасывается ДО того, как в него
// уйдёт первый запрос. 300с = ConnIdleTimeout нашего порта Xray
// (common/xray/net) и примерно то, что делает Chrome со своими h2-сокетами.
const (
	dohReadIdleTimeout = 5 * time.Second
	dohPingTimeout     = 4 * time.Second
	dohIdleConnTimeout = 300 * time.Second
)

type HTTPSTransportWrapper struct {
	http2Transport *http2.Transport
	httpTransport  *http.Transport
	fallback       *atomic.Bool
}

func NewHTTPSTransportWrapper(dialer tls.Dialer, serverAddr M.Socksaddr) *HTTPSTransportWrapper {
	var fallback atomic.Bool
	return &HTTPSTransportWrapper{
		http2Transport: &http2.Transport{
			// Health-check мёртвого коннекта после сна девайса — см. константы выше.
			ReadIdleTimeout: dohReadIdleTimeout,
			PingTimeout:     dohPingTimeout,
			IdleConnTimeout: dohIdleConnTimeout,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.STDConfig) (net.Conn, error) {
				tlsConn, err := dialer.DialTLSContext(ctx, serverAddr)
				if err != nil {
					return nil, err
				}
				state := tlsConn.ConnectionState()
				if state.NegotiatedProtocol == http2.NextProtoTLS {
					return tlsConn, nil
				}
				tlsConn.Close()
				fallback.Store(true)
				return nil, errFallback
			},
		},
		httpTransport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialTLSContext(ctx, serverAddr)
			},
		},
		fallback: &fallback,
	}
}

func (h *HTTPSTransportWrapper) RoundTrip(request *http.Request) (*http.Response, error) {
	if h.fallback.Load() {
		return h.httpTransport.RoundTrip(request)
	} else {
		response, err := h.http2Transport.RoundTrip(request)
		if err != nil {
			if errors.Is(err, errFallback) {
				return h.httpTransport.RoundTrip(request)
			}
			return nil, err
		}
		return response, nil
	}
}

func (h *HTTPSTransportWrapper) CloseIdleConnections() {
	h.http2Transport.CloseIdleConnections()
	h.httpTransport.CloseIdleConnections()
}

func (h *HTTPSTransportWrapper) Clone() *HTTPSTransportWrapper {
	return &HTTPSTransportWrapper{
		httpTransport: h.httpTransport,
		http2Transport: &http2.Transport{
			// Health-check переносим в клон — Clone() зовётся из https.go на
			// каждый Reset/DeadlineExceeded; без копирования этих полей первый
			// же сброс транспорта молча выключал бы health-check навсегда.
			ReadIdleTimeout: h.http2Transport.ReadIdleTimeout,
			PingTimeout:     h.http2Transport.PingTimeout,
			IdleConnTimeout: h.http2Transport.IdleConnTimeout,
			DialTLSContext:  h.http2Transport.DialTLSContext,
		},
		fallback: h.fallback,
	}
}
