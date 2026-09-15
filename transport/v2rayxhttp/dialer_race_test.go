package xhttp

// Регрессии на две дыры в DefaultDialerClient.OpenStream, закрытые 2026-09-15:
//
//   - колбэк httptrace.GotConn срабатывает ОДИН РАЗ НА ПОПЫТКУ, а не один раз
//     на client.Do. Родитель просыпается на первом срабатывании (gotConn —
//     done.Instance, sync.Once) и читает адреса, пока колбэк повтора их пишет.
//     Свойство, которое проверяем: побеждает ПЕРВАЯ попытка, при любом числе
//     последующих срабатываний и без гонки данных.
//   - http.NewRequestWithContext возвращал ошибку в `_`, и следующая строка
//     разыменовывала nil-req. Метод аплинка приходит из чужой подписки, то есть
//     это падение процесса от чужого конфига.

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// stubConn — минимальный net.Conn, который нужен httptrace.GotConnInfo: из него
// читаются только адреса.
type stubConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (c stubConn) RemoteAddr() net.Addr { return c.remote }
func (c stubConn) LocalAddr() net.Addr  { return c.local }

// retryingRoundTripper воспроизводит ровно то, что делают все три наших
// транспорта на повторе: зовёт GotConn первой попытки (этим освобождая
// родителя), а затем — из ОТДЕЛЬНОЙ горутины, без всякой синхронизации с
// родителем — GotConn второй попытки с ДРУГИМИ адресами.
//
// См. replace/x-net/http2/transport_common.go:338-345 (traceGotConn внутри
// `for retry := 0; ; retry++`), net/http Transport.roundTrip → getConn на
// мёртвом keep-alive-соединении, quic-go http3 doRoundTripOpt, плюс редиректы
// внутри client.Do — каждый из них новый RoundTrip с тем же ClientTrace.
type retryingRoundTripper struct {
	first  net.Addr
	second net.Addr
	done   *sync.WaitGroup
}

func (rt retryingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: stubConn{remote: rt.first, local: rt.first}})
		rt.done.Add(1)
		go func() {
			defer rt.done.Done()
			trace.GotConn(httptrace.GotConnInfo{Conn: stubConn{remote: rt.second, local: rt.second}})
		}()
	}
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

// Свойство: сколько бы раз колбэк ни сработал, OpenStream отдаёт адрес ПЕРВОЙ
// попытки — той самой, по которой он и разблокировался.
//
// На прежнем коде (колбэк писал в общие переменные простым присваиванием) этот
// тест падает двумя способами сразу: под `go test -race` — WARNING: DATA RACE
// на tracedRemoteAddr/tracedLocalAddr, и без -race — выигрывает запись второй
// попытки, то есть assert'ом.
func TestOpenStreamGotConnFirstAttemptWins(t *testing.T) {
	firstAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1111}
	secondAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2222}

	var callbacks sync.WaitGroup
	options := option.V2RayXHTTPBaseOptions{}
	client := &DefaultDialerClient{
		options: &options,
		client: &http.Client{Transport: retryingRoundTripper{
			first:  firstAddr,
			second: secondAddr,
			done:   &callbacks,
		}},
		httpVersion:   "1.1",
		uploadRawPool: &sync.Pool{},
	}

	for i := 0; i < 500; i++ {
		reader, remoteAddr, localAddr, err := client.OpenStream(context.Background(), "http://example.invalid/", nil, false)
		if err != nil {
			t.Fatalf("итерация %d: OpenStream: %v", i, err)
		}
		if remoteAddr != net.Addr(firstAddr) {
			t.Fatalf("итерация %d: remoteAddr = %v, ожидался адрес первой попытки %v", i, remoteAddr, firstAddr)
		}
		if localAddr != net.Addr(firstAddr) {
			t.Fatalf("итерация %d: localAddr = %v, ожидался адрес первой попытки %v", i, localAddr, firstAddr)
		}
		if reader != nil {
			_ = reader.Close()
		}
	}
	callbacks.Wait()
}

// То же самое, но повтор настоящий, а не смоделированный: сервер отвечает и
// сразу закрывает соединение, поэтому следующий OpenStream достаёт из пула
// net/http уже мёртвый conn, получает ошибку и повторяет запрос — GotConn
// срабатывает дважды внутри ОДНОГО client.Do. Смысл теста — под -race; без
// него он лишь проверяет, что путь повтора не ломает дозвон.
func TestOpenStreamGotConnFiresPerAttempt(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("слушать порт: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			serverConn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, readErr := reader.ReadString('\n')
					if readErr != nil {
						return
					}
					if strings.TrimSpace(line) == "" {
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
						// Закрываем сразу: следующий запрос возьмёт этот conn из
						// пула раньше, чем readLoop заметит EOF, и уйдёт в повтор.
						return
					}
				}
			}(serverConn)
		}
	}()

	transport := &http.Transport{MaxIdleConnsPerHost: 8}
	defer transport.CloseIdleConnections()
	options := option.V2RayXHTTPBaseOptions{}
	client := &DefaultDialerClient{
		options:       &options,
		client:        &http.Client{Transport: transport},
		httpVersion:   "1.1",
		uploadRawPool: &sync.Pool{},
	}
	url := "http://" + listener.Addr().String() + "/"
	for i := 0; i < 300; i++ {
		reader, _, _, openErr := client.OpenStream(context.Background(), url, nil, false)
		if openErr != nil {
			t.Fatalf("итерация %d: OpenStream: %v", i, openErr)
		}
		if reader != nil {
			_ = reader.Close()
		}
	}
}

// Метод аплинка приходит из подписки без валидации. Кривой метод обязан стать
// неудачным диалом, а не паникой в ядре VPN. До фикса здесь был nil pointer
// dereference: `req, _ := http.NewRequestWithContext(...)` и сразу `req.Header`.
func TestOpenStreamInvalidUplinkMethodReturnsError(t *testing.T) {
	for _, method := range []string{"POST X", "PO ST", "POST\n", "GET\tX"} {
		t.Run(method, func(t *testing.T) {
			options := option.V2RayXHTTPBaseOptions{UplinkHTTPMethod: method}
			client := &DefaultDialerClient{
				options:       &options,
				client:        &http.Client{Transport: &http.Transport{}},
				httpVersion:   "1.1",
				uploadRawPool: &sync.Pool{},
			}
			// body != nil ⇒ метод берётся из подписки (stream-up/stream-one).
			reader, _, _, err := client.OpenStream(context.Background(), "http://127.0.0.1:1/", strings.NewReader(""), true)
			if err == nil {
				if reader != nil {
					_ = reader.Close()
				}
				t.Fatalf("кривой метод %q принят без ошибки", method)
			}
			if reader != nil {
				t.Fatalf("при ошибке OpenStream обязан вернуть nil-reader, вернул %T", reader)
			}
		})
	}
}
