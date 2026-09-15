package xhttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go/http3"
	common "github.com/sagernet/sing-box/common/xray"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/net/http2"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool

	// ctx, url, body, uploadOnly
	OpenStream(context.Context, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, body, contentLength
	PostPacket(context.Context, string, io.Reader, int64) error
}

// implements xhttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	options *option.V2RayXHTTPBaseOptions
	client  *http.Client
	// logger — тот же user-facing канал, что у Client (box.log → gRPC log-стрим
	// → вкладка «Логи»). InHive 2026-08-03: до этого у дозвонщика логгера не
	// было вовсе, и ВЕСЬ класс отказов открытия стрима был немым — см. logDial.
	// nil допустим (тесты, download-detour без логгера); все вызовы nil-safe.
	logger logger.ContextLogger
	// closed — «этот клиент больше не годен для переиспользования».
	//
	// InHive 2026-09-15, порт Xray 77f98eba (PR #6665, вошёл в 26.9.9): было
	// голое `bool`, и это настоящая гонка данных, а не формальность. ПИШУТ его
	// три разные горутины: горутина ответа OpenStream (отказ client.Do), любая
	// из параллельных POST-горутин packet-up (PostPacket, их десятки в полёте) и
	// Close() из пула xmux. ЧИТАЕТ его IsClosed() — из XmuxManager
	// (mux.go getXmuxClientLocked, под СВОИМ mtx, который с этими писателями
	// никакого happens-before не создаёт) и из Probe/Sweep-путей. То есть
	// каждый prune пула читает флаг, который в этот момент пишет чужая горутина.
	// Апстрим закрыл это тем же способом — atomic.Bool.
	closed      atomic.Bool
	httpVersion string
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

// logDial озвучивает отказ ДОЗВОНА (открытия HTTP-стрима) в пользовательский лог.
//
// InHive 2026-08-03: раньше здесь была тишина. `OpenStream` глотал и ошибку
// `client.Do`, и non-200 (`wrc.Close(); return`), а вызывающий код в client.go
// проверяет возвращённую ошибку только ради browser dialer — у сетевого
// дозвонщика ошибка живёт в горутине и наверх не идёт вообще. Наблюдаемый
// эффект: транспорт «дозвонился», прокси-conn открыт, данные не текут, и
// пользователь видит лишь `context deadline exceeded` от urltest.
//
// Цена этой немоты измерена: отказ REALITY-auth (сервер с `minClientVer`
// отдаёт настоящий сертификат dest, TLS падает с x509-ошибкой) на xhttp-пути
// не давал НИ ОДНОЙ строчки, хотя на обычном пути тот же отказ читается как
// `reality verification failed`. Диагностировать пришлось ручной
// инструментацией ядра. Ровно класс «отказ невидим» — такой обязан быть
// озвучен, а не выведен постфактум.
func (c *DefaultDialerClient) logDial(ctx context.Context, message string) {
	if c.logger == nil {
		return
	}
	c.logger.WarnContext(ctx, message)
}

// Close помечает клиента закрытым и АКТИВНО закрывает соединения его пулов.
//
// InHive 2026-07-19: клиент после Close ВЫБРАСЫВАЕТСЯ (XmuxManager.Reset
// вычёркивает его из пула; IsClosed()==true не даст переиспользовать), поэтому
// восстанавливать работоспособность транспорта не нужно — новый диал получит
// СВЕЖИЙ DefaultDialerClient из newConnFunc. Задача здесь — не оставить живых
// (или мёртвых после сна) TCP/QUIC-сессий без владельца:
//   - h2: рабочий образец в дереве — v2rayhttp.ResetTransport
//     (transport/v2rayhttp/force_close.go): закрывает ВСЕ соединения приватного
//     пула http2 через go:linkname. Именно h2 держал тёплый пул xmux с мёртвым
//     TCP после пробуждения Windows.
//   - h1: у http.Transport DisableKeepAlives=true (пула idle-соединений нет,
//     CloseIdleConnections — страховка); реальный пул h1-аплоада —
//     uploadRawPool с сырыми conn'ами, его дренируем и закрываем.
//   - h3: http3.Transport.Close() закрывает QUIC-соединения; после Close этот
//     transport непереиспользуем ("A Transport cannot be used after it has
//     been closed") — не проблема, см. выше: клиент одноразовый.
func (c *DefaultDialerClient) Close() error {
	c.closed.Store(true)
	if c.client == nil {
		return nil
	}
	switch transport := c.client.Transport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
		for {
			pooled := c.uploadRawPool.Get()
			if pooled == nil {
				break
			}
			if conn, isConn := pooled.(*H1Conn); isConn {
				_ = conn.Close()
			}
		}
	case *http2.Transport:
		v2rayhttp.ResetTransport(transport)
	case *http3.Transport:
		_ = transport.Close()
	}
	return nil
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, body io.Reader, uploadOnly bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	//
	// InHive 2026-09-15: колбэк GotConn исполняется в ЧУЖОЙ горутине (внутри
	// client.Do) и может сработать НЕ ОДИН РАЗ за один вызов Do. Это не теория,
	// а устройство всех трёх наших транспортов:
	//   - вендоренный x/net/http2 зовёт traceGotConn на КАЖДОЙ итерации цикла
	//     повтора (replace/x-net/http2/transport_common.go:338-345 — повтор на
	//     GOAWAY / errClientConnUnusable / REFUSED_STREAM). У stream-down GET
	//     тело == nil, поэтому shouldRetryRequest отдаёт тот же запрос назад
	//     безусловно — это ровно тот запрос, который повторяется чаще всего;
	//   - net/http Transport.roundTrip так же переспрашивает getConn (а тот
	//     зовёт trace.GotConn), когда взятое из пула keep-alive-соединение
	//     оказалось уже мёртвым — обычное дело за CDN и после сна девайса;
	//   - quic-go http3.Transport делает то же в doRoundTripOpt;
	//   - и сверх того client.Do идёт по редиректам, а каждый редирект — новый
	//     RoundTrip с тем же ClientTrace.
	//
	// gotConn — done.Instance (sync.Once), поэтому родителя освобождает только
	// ПЕРВОЕ срабатывание. Значит колбэк, пишущий в общие переменные, пишет их
	// уже ПОСЛЕ того, как родитель проснулся и читает, — незасинхронизированный
	// read/write двух интерфейсных значений по два машинных слова каждое, то
	// есть тот же класс torn read, что мы чинили в WaitReadCloser. Прежняя
	// правка (писать в локальные переменные вместо именованных результатов)
	// гонку не убирала, а только переносила: окно на повторах оставалось
	// открытым, и комментарий здесь утверждал happens-before, которого для
	// второго и последующих срабатываний нет. Воспроизводится под
	// `go test -race` — см. TestOpenStreamGotConnFiresPerAttempt.
	//
	// Публикуем пару одним atomic.Pointer на НЕИЗМЕНЯЕМУЮ структуру и ставим её
	// через CompareAndSwap: побеждает первая попытка — ровно та, по которой
	// родитель и разблокировался, — а все последующие срабатывания становятся
	// no-op. Мутации на месте нет вовсе, поэтому сколько бы раз колбэк ни
	// сработал, читателю нечего рвать.
	//
	// Это СОЗНАТЕЛЬНОЕ усиление против апстрима: Xray v26.9.9
	// (transport/internet/splithttp/client.go) по-прежнему пишет из колбэка
	// прямо в именованные результаты и несёт ту же гонку. Побочно это закрывает
	// и унаследованную от hiddify ветку `<-ctx.Done()` в select ниже (коммит
	// f356a2972 2026-01-30), которой у апстрима нет вовсе: сегодня она
	// недостижима (client.go передаёт сюда uploadCtx, не отменяемый до возврата
	// из DialContext), но «недостижимо» — не «безопасно».
	type tracedAddrs struct {
		remote net.Addr
		local  net.Addr
	}
	var tracedAddr atomic.Pointer[tracedAddrs]
	gotConn := done.New()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			tracedAddr.CompareAndSwap(nil, &tracedAddrs{
				remote: connInfo.Conn.RemoteAddr(),
				local:  connInfo.Conn.LocalAddr(),
			})
			gotConn.Close()
		},
	})
	method := "GET" // stream-down
	if body != nil {
		method = c.options.GetNormalizedUplinkHTTPMethod() // stream-up/one (default POST)
	}
	// InHive 2026-07-19: НЕ оборачиваем в context.WithoutCancel.
	//
	// Апстрим (Xray splithttp/client.go) вынужден это делать, потому что ему сюда
	// передают DIAL-контекст, который отменяется сразу после возврата из Dial —
	// без отвязки каждый стрим умирал бы мгновенно. Цена отвязки: у запроса вообще
	// не остаётся владельца, он не отменяется НИКОГДА (единственное, что его в
	// итоге убивает — h2 health-check через ReadIdleTimeout 45с + pingTimeout 15с,
	// отсюда обрывы ровно на «1m0s» в наших логах).
	//
	// Мы вместо этого передаём сюда контекст ЖИЗНИ СОЕДИНЕНИЯ (client.go
	// DialContext: WithoutCancel(dial-ctx) + WithCancel, cancel в conn.onClose).
	// Он не отменяется по завершении дозвона (то самое, ради чего апстрим ставил
	// WithoutCancel), но отменяется при закрытии проксируемого conn — то есть у
	// запроса появляется корректный владелец. Это и есть замена снятой правки с
	// ctx-проверками в WaitReadCloser.Read: та рвала стрим по dial-контексту
	// (слишком рано), эта — по закрытию соединения (ровно тогда, когда надо).
	// InHive 2026-07-19: заголовки считаем ДО построения запроса, потому что
	// GetRequestHeader может изменить сам URL (placement "query" дописывает в него
	// padding). Раньше запрос строился первым, а изменённый URL выбрасывался — padding
	// не уезжал на провод, сервер отвергал каждый такой запрос, и в нашем логе не было
	// ни строчки.
	header, effectiveURL := c.options.GetRequestHeader(url)
	// InHive 2026-09-15: ошибку построения запроса НЕЛЬЗЯ глотать — раньше здесь
	// стояло `req, _ :=`, а следующая же строка разыменовывала req.
	//
	// Это не гигиена, а падение процесса от ЧУЖОГО конфига: на пути
	// stream-up/stream-one method берётся из GetNormalizedUplinkHTTPMethod()
	// (option/v2ray_transport.go), то есть напрямую из подписки, без валидации.
	// Любой метод с пробелом или управляющим символом («POST X») даёт
	// `net/http: invalid method`, req == nil и nil pointer dereference в ядре
	// VPN. PostPacket ниже эту ошибку обрабатывает корректно — файл расходился
	// сам с собой. Апстрим (Xray v26.9.9 splithttp/client.go) проверяет её здесь
	// точно так же. Все три вызова OpenStream в client.go возвращаемую ошибку
	// пробрасывают, так что отказ вырождается в неудачный диал.
	req, err := http.NewRequestWithContext(ctx, method, effectiveURL, body)
	if err != nil {
		c.logDial(ctx, F.ToString("xhttp: cannot build ", method, " request for ", effectiveURL, ": ", err))
		return nil, nil, nil, err
	}
	req.Header = header
	if body != nil && !c.options.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}
	// InHive 2026-08-01: negotiation фрейминга stream-down (Xray PR #6562).
	//
	// Маркер кладём ТОЛЬКО на download-GET и ТОЛЬКО если клиент явно включил
	// downFrame. Порядок как в PR B: сначала считается padding (GetRequestHeader
	// выше — аналог FillStreamRequest), потом дописывается маркер, поэтому
	// длина x_padding не съезжает. Ключ по умолчанию "x_df" — это ЧАСТЬ ПРОВОДА,
	// совпадает с апстримом побайтово.
	//
	// GET здесь = download-половина packet-up И stream-up (у обоих body == nil);
	// stream-one идёт с телом → method = uplink method → маркера не получает.
	// Ровно та же граница, что в PR B (`method == "GET" && cfg.DownFrame`).
	downFrameRequested := method == http.MethodGet && c.options.DownFrame
	if downFrameRequested {
		query := req.URL.Query()
		query.Set(c.options.GetNormalizedDownFrameKey(), "1")
		req.URL.RawQuery = query.Encode()
	}
	wrc = &WaitReadCloser{wait: done.New()}
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			c.logDial(ctx, F.ToString("xhttp: ", method, " stream failed: ", err))
			if !uploadOnly { // stream-down is enough
				c.closed.Store(true)
			}
			gotConn.Close()
			wrc.Close()
			return
		}
		if resp.StatusCode != 200 {
			c.logDial(ctx, F.ToString("xhttp: ", method, " stream rejected by server: HTTP ", resp.StatusCode))
		}
		if resp.StatusCode != 200 || uploadOnly { // stream-up
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close() // if it is called immediately, the upload will be interrupted also
			wrc.Close()
			return
		}
		// Стриппер включаем ТОЛЬКО если сами просили И сервер подтвердил
		// заголовком. Без подтверждения (старый/непатченый сервер, CDN срезал
		// заголовок) читаем сырой поток — то есть ровно сегодняшнее поведение.
		if downFrameRequested && resp.Header.Get(downFrameConfirmHeader) == "1" {
			wrc.(*WaitReadCloser).Set(newFramedReader(resp.Body))
			return
		}
		wrc.(*WaitReadCloser).Set(resp.Body)
	}()
	select {
	case <-gotConn.Wait():
		// Единственное место, где адреса читаются. Публикация — atomic.Pointer,
		// поэтому чтение корректно независимо от того, сколько ещё раз колбэк
		// сработает после нашего пробуждения (см. разбор повторов выше).
		// На путях отказа client.Do gotConn закрывает сама горутина ответа, и
		// колбэк мог не сработать вовсе — тогда Load() даёт nil и адреса
		// остаются нулевыми, ровно как и раньше.
		if addrs := tracedAddr.Load(); addrs != nil {
			remoteAddr, localAddr = addrs.remote, addrs.local
		}
	case <-ctx.Done():
	}
	return
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, body io.Reader, contentLength int64) error {
	// InHive 2026-07-19: ctx здесь — контекст ЖИЗНИ СОЕДИНЕНИЯ (см. развёрнутое
	// обоснование в OpenStream выше), поэтому context.WithoutCancel снят.
	//
	// Это и есть «правильная защита» вместо снятого `select { <-ctx.Done() }` в
	// цикле отправки: тот ломал упорядоченность seq (цикл переставал сериализовать
	// POST'ы), а зависший POST всё равно не отменял. Теперь зависший POST живёт
	// ровно до закрытия проксируемого conn и умирает вместе с ним, не утекая
	// горутиной и не удерживая свой чанк.
	// InHive 2026-07-19: см. OpenStream выше — URL берём из GetRequestHeader, иначе
	// padding при placement "query" не попадает в запрос.
	header, effectiveURL := c.options.GetRequestHeader(url)
	req, err := http.NewRequestWithContext(ctx, c.options.GetNormalizedUplinkHTTPMethod(), effectiveURL, body)
	if err != nil {
		return err
	}
	req.ContentLength = contentLength
	req.Header = header
	// InHive 2026-09-15, порт Xray dffc7ada (PR #6632, вошёл в 26.9.9): тело
	// packet-up POST'а обязано быть ПЕРЕИГРЫВАЕМЫМ, иначе h2/h3 теряет запрос на
	// GOAWAY. Апстрим ставит GetBody в Config.FillPacketRequest (материализует
	// payload в []byte); у нас тело приходит параметром, поэтому делаем это здесь
	// — PostPacket единственная точка сборки packet-up запроса, так что свойство
	// принадлежит транспорту, а не вызывающему коду.
	//
	// Механика отказа, который это чинит (вендоренный x/net/http2,
	// replace/x-net/http2): setGoAway() обрывает ровно те стримы, у которых ID >
	// LastStreamID — то есть те, которые сервер ГАРАНТИРОВАННО не обработал, —
	// ошибкой errClientConnGotGoAway. roundTripViaPool ловит её и зовёт
	// shouldRetryRequest (transport_common.go:395): тело есть, GetBody нет →
	// «cannot retry err [...] after Request.Body was written; define
	// Request.GetBody to avoid this error». Телом у нас был одноразовый
	// buf.MultiBufferContainer, для которого net/http GetBody не выводит (он
	// умеет только *bytes.Reader/*bytes.Buffer/*strings.Reader), — значит КАЖДЫЙ
	// GOAWAY (ротация h2-соединения на CDN, graceful shutdown origin'а,
	// hMaxRequestTimes на той стороне) ронял POST, а client.go на ошибку POST'а
	// делает uploadPipeReader.Interrupt() — то есть убивал ВСЮ upload-половину
	// сессии, а не один чанк. Тот же механизм и в h3 (quic-go http3
	// canRetryRequest, повтор только на H3_REQUEST_REJECTED).
	//
	// Почему повтор безопасен при нашей строгой нумерации seq:
	//   - переигрывается ТОТ ЖЕ req (shouldRetryRequest делает поверхностную
	//     копию — тот же URL, тот же seq, тот же padding), дубля seq не возникает;
	//   - и h2, и h3 повторяют ТОЛЬКО то, что сервер по протоколу не обрабатывал
	//     (ID > LastStreamID / REFUSED_STREAM / H3_REQUEST_REJECTED), значит
	//     оригинал до upload_queue не доехал и дырки в нумерации тоже не будет;
	//   - если повтор разъедется по времени с соседним POST'ом, upload_queue на
	//     сервере пересобирает по seq (heap до scMaxBufferedPosts) — ровно тот
	//     случай, ради которого он написан.
	// Альтернатива «не переигрывать» — не «чуть хуже», а обрыв сессии.
	//
	// Цена: одна копия чанка на POST (у апстрима такая же). Пулевые буферы
	// отдаём в пул сразу — иначе чанк держался бы до конца запроса.
	if req.Body != nil && req.GetBody == nil && contentLength >= 0 {
		data := make([]byte, contentLength)
		if _, readErr := io.ReadFull(req.Body, data); readErr != nil {
			req.Body.Close()
			return readErr
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(data))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}
	}
	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed.Store(true)
			return err
		}
		io.Copy(io.Discard, resp.Body)
		defer resp.Body.Close()
		// InHive 2026-07-19: parity с Xray (splithttp/client.go — там проверка есть
		// на ОБОИХ путях; у нас была только на h1-ветке ниже). Без неё отказ сервера
		// (405/400/5xx) возвращался как err == nil ⇒ POST считался доставленным, а его
		// `seq` терялся НАВСЕГДА. Приёмная сторона (upload_queue) собирает пакеты
		// строго по порядку и держит все последующие, ожидая пропавший — то есть одна
		// проглоченная ошибка встаёт головой очереди и душит сессию, маскируясь под
		// «медленную сеть». Device-verified 2026-07-19: клиент рапортовал 46 Мбит/с
		// отправки при 0.75 Мбит/с реально доехавших.
		if resp.StatusCode != 200 {
			return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
		}
	} else {
		// stringify the entire HTTP/1.1 request so it can be
		// safely retried. if instead req.Write is called multiple
		// times, the body is already drained after the first
		// request
		requestBuff := new(bytes.Buffer)
		common.Must(req.Write(requestBuff))
		var uploadConn any
		var h1UploadConn *H1Conn
		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				newConn, err := c.dialUploadConn(context.WithoutCancel(ctx))
				if err != nil {
					return err
				}
				h1UploadConn = NewH1Conn(newConn)
				uploadConn = h1UploadConn
			} else {
				h1UploadConn = uploadConn.(*H1Conn)

				// TODO: Replace 0 here with a config value later
				// Or add some other condition for optimization purposes
				if h1UploadConn.UnreadedResponsesCount > 0 {
					resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
					if err != nil {
						c.closed.Store(true)
						return fmt.Errorf("error while reading response: %s", err.Error())
					}
					io.Copy(io.Discard, resp.Body)
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
					}
				}
			}
			_, err := h1UploadConn.Write(requestBuff.Bytes())
			// if the write failed, we try another connection from
			// the pool, until the write on a new connection fails.
			// failed writes to a pooled connection are normal when
			// the connection has been closed in the meantime.
			if err == nil {
				break
			} else if newConnection {
				return err
			}
		}
		c.uploadRawPool.Put(uploadConn)
	}

	return nil
}

// InHive 2026-07-19: поле ctx и его проверки в Read убраны — parity с Xray
// (splithttp/client.go WaitReadCloser). Наша правка рвала download-стрим по
// dial-контексту, тогда как апстрим СОЗНАТЕЛЬНО отвязывает стрим от него
// (запросы строятся с context.WithoutCancel). Получалась асимметричная смерть
// сессии: приём падал с `context canceled` / `read/write on closed pipe`, а
// upload-горутина продолжала жить — сессия наполовину мертва, порядок seq
// нарушен, сервер встаёт головой очереди.
// InHive 2026-08-01: у Xray поле было голым встроенным `io.ReadCloser`:
// Set() пишет его из горутины ответа OpenStream, а Read()/Close() читают из
// горутины читателя БЕЗ синхронизации. Интерфейсное значение — это два
// машинных слова, так что это не «ложный шум детектора», а настоящий torn
// read: читатель может увидеть type-слово от нового значения с data-словом
// от старого. Подтверждено go test -race (гонка воспроизводится и с
// downFrame:false — к фреймингу отношения не имеет, это общий reader всех
// режимов xhttp). Мы закрыли её atomic.Pointer'ом.
//
// InHive 2026-09-15: апстрим независимо починил ТУ ЖЕ гонку — Xray eef6e63b
// (PR #6694, вошёл в 26.9.9) — и пришёл к той же atomic.Pointer-форме. Берём
// апстримную целиком, потому что она СИЛЬНЕЕ нашей в трёх местах, и каждое
// из трёх у нас реально достижимо:
//
//   - `reader.Swap(nil)` вместо `Load()` ⇒ нижележащий Body закрывается РОВНО
//     ОДИН раз. У нас двойной Close был штатным сценарием, а не экзотикой:
//     conn.Close() (conn.go) зовёт reader.Close(), а горутина ответа на non-200
//     зовёт wrc.Close() — оба раза по одному и тому же resp.Body. Для h2-тела
//     это сходило с рук, для нашего framedReader (framer.go) — тоже, но
//     свойство «закрыть ровно один раз» держится структурой, а не везением.
//   - Close() теперь ВСЕГДА закрывает wait ⇒ читатель, стоящий в `<-wait`,
//     гарантированно освобождается и получает io.ErrClosedPipe. В нашей версии
//     ветка `rc != nil` возвращалась, не трогая wait, и корректность держалась
//     на рассуждении «Set всё равно закроет канал следом» — рассуждение верное,
//     но лишнее.
//   - Read после Close возвращает io.ErrClosedPipe, а не лезет читать из уже
//     закрытого Body (Swap(nil) обнуляет указатель) — детерминированная ошибка
//     вместо «что вернёт закрытое тело».
//
// done.Instance вместо `chan struct{}` + recover: двойное закрытие у него
// идемпотентно (sync.Once), поэтому гонка Set-против-Close ловится честной
// проверкой wait.Done(), а не паникой как сигналом. Панику мы держали только
// ради parity с 26.7.11 — теперь parity ровно наоборот.
//
// НАШЕ расхождение, которое здесь сохраняется: Set может получить не голый
// resp.Body, а framedReader поверх него (stream-down keepalive, framer.go) —
// это по-прежнему обычный io.ReadCloser, и вся механика выше работает с ним
// без изменений.
type WaitReadCloser struct {
	wait   *done.Instance
	reader atomic.Pointer[io.ReadCloser]
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.reader.Store(&rc)
	if w.wait.Done() {
		if p := w.reader.Swap(nil); p != nil {
			(*p).Close()
		}
	}
	w.wait.Close()
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	rc := w.reader.Load()
	if rc == nil {
		<-w.wait.Wait()
		if rc = w.reader.Load(); rc == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return (*rc).Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.wait.Close()
	if p := w.reader.Swap(nil); p != nil {
		return (*p).Close()
	}
	return nil
}

// ProbeConns — InHive 2026-09-08: проверка h2-пула этого клиента PING'ом после
// сна девайса (см. v2rayhttp.ProbeTransport). h1 — пула idle-соединений нет
// (DisableKeepAlives), h3 — QUIC сам держит keepalive/idle-таймер: для них
// проверять нечего, (0, 0).
func (c *DefaultDialerClient) ProbeConns(ctx context.Context, timeout time.Duration) (probed int, closed int) {
	if c.client == nil {
		return 0, 0
	}
	if transport, isH2 := c.client.Transport.(*http2.Transport); isH2 {
		return v2rayhttp.ProbeTransport(ctx, transport, timeout)
	}
	return 0, 0
}
