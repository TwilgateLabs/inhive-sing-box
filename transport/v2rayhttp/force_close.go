package v2rayhttp

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

type clientConnPool struct {
	t     *http2.Transport
	mu    sync.Mutex
	conns map[string][]*http2.ClientConn // key is host:port
}

type efaceWords struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}

func ResetTransport(rawTransport http.RoundTripper) http.RoundTripper {
	switch transport := rawTransport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
		return transport.Clone()
	case *http2.Transport:
		connPool := transportConnPool(transport)
		p := (*clientConnPool)((*efaceWords)(unsafe.Pointer(&connPool)).data)
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, vv := range p.conns {
			for _, cc := range vv {
				cc.Close()
			}
		}
		return transport
	default:
		panic(E.New("unknown transport type: ", reflect.TypeOf(transport)))
	}
}

//go:linkname transportConnPool golang.org/x/net/http2.(*Transport).connPool
func transportConnPool(t *http2.Transport) http2.ClientConnPool

// ProbeTransport — InHive 2026-09-08: «спросить сеть, а не решать по времени».
//
// Шлёт HTTP/2 PING по каждому живому ClientConn приватного пула транспорта
// (тот же go:linkname-доступ, что у ResetTransport) и закрывает ТОЛЬКО те,
// что не ответили за timeout. Живые соединения — включая занятые стримами —
// не трогаются. Это замена сбросу пула по факту wake() на iOS: sleep/wake там
// приходят на каждую блокировку/подсветку экрана (раз в 6–50 с), и
// безусловный ResetTransport рвал живые загрузки (device-дамп 2026-09-07:
// 33 из 34 срабатываний — по живым соединениям).
//
// Почему timeout снаружи, а не константа: вызывающий обязан передать не
// меньше штатного http2 PingTimeout (15 с). PING-ack читается readLoop'ом
// ПОСЛЕ всех DATA-фреймов в приёмном буфере (до 1 МБ на xhttp-эджах), а первая
// секунда после пробуждения уходит на подъём радио — короткий таймаут (2 с)
// объявляет мёртвым соединение под нагрузкой, т.е. воспроизводит тот же баг
// мягче. Ошибочный Ping ⇒ cc.Close() ⇒ closeForError: in-flight стримы этого
// (и только этого) соединения падают, пул выкидывает его через MarkDead,
// следующий запрос дозванивается заново.
//
// Снимок списка соединений — под p.mu, сами PING'и — параллельно и ВНЕ лока:
// иначе проба на 15 с блокировала бы ResetTransport от реальной смены сети.
// Уже закрытые/закрывающиеся соединения пропускаются (не считаются).
func ProbeTransport(ctx context.Context, transport *http2.Transport, timeout time.Duration) (probed int, closed int) {
	connPool := transportConnPool(transport)
	p := (*clientConnPool)((*efaceWords)(unsafe.Pointer(&connPool)).data)
	p.mu.Lock()
	var conns []*http2.ClientConn
	for _, vv := range p.conns {
		for _, cc := range vv {
			state := cc.State()
			if state.Closed || state.Closing {
				continue
			}
			conns = append(conns, cc)
		}
	}
	p.mu.Unlock()
	if len(conns) == 0 {
		return 0, 0
	}
	var failed atomic.Int32
	var wg sync.WaitGroup
	for _, cc := range conns {
		wg.Add(1)
		go func(cc *http2.ClientConn) {
			defer wg.Done()
			pingCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			if err := cc.Ping(pingCtx); err != nil {
				failed.Add(1)
				_ = cc.Close()
			}
		}(cc)
	}
	wg.Wait()
	return len(conns), int(failed.Load())
}
