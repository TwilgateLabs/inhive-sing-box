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

	"github.com/sagernet/quic-go/http3"
	common "github.com/sagernet/sing-box/common/xray"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"

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
	options     *option.V2RayXHTTPBaseOptions
	client      *http.Client
	closed      bool
	httpVersion string
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed
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
	c.closed = true
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
	gotConn := done.New()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
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
	req, _ := http.NewRequestWithContext(ctx, method, effectiveURL, body)
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
	wrc = &WaitReadCloser{Wait: make(chan struct{})}
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly { // stream-down is enough
				c.closed = true
			}
			gotConn.Close()
			wrc.Close()
			return
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
	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed = true
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
						c.closed = true
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
type WaitReadCloser struct {
	Wait chan struct{}
	io.ReadCloser
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.ReadCloser = rc
	defer func() {
		if recover() != nil {
			rc.Close()
		}
	}()
	close(w.Wait)
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	if w.ReadCloser == nil {
		if <-w.Wait; w.ReadCloser == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return w.ReadCloser.Read(b)
}

func (w *WaitReadCloser) Close() error {
	if w.ReadCloser != nil {
		return w.ReadCloser.Close()
	}
	defer func() {
		if recover() != nil && w.ReadCloser != nil {
			w.ReadCloser.Close()
		}
	}()
	close(w.Wait)
	return nil
}
