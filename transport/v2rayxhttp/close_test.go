package xhttp

// Тесты контракта Close() (InHive 2026-07-19, сон/пробуждение Windows).
//
// Контракт sing-box: InterfaceUpdated() у vless/vmess/trojan зовёт
// transport.Close(), чтобы транспорт передиалился свежим соединением. Эти
// тесты закрывают ровно ту дыру, из-за которой xhttp после пробуждения висел
// на мёртвом тёплом пуле xmux: наполняем пул по РЕАЛЬНОМУ сокету, дёргаем
// Close()/Reset() и проверяем фактом, что
//   1) все старые TCP-соединения ЗАКРЫТЫ (не утекли и не переиспользуются),
//   2) следующий диал создаёт НОВОЕ соединение,
//   3) клиент после Close ОСТАЁТСЯ РАБОЧИМ (семантика «сброс», не
//      «уничтожение») — иначе вместо 45с ожидания получили бы полную поломку.

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// trackedConn помечает Close — единственный надёжный клиентский способ
// убедиться, что пул закрыл СВОИ соединения (h2 закрывает их через приватный
// пул x/net, снаружи его не видно).
type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// trackingDialer реализует N.Dialer поверх net.Dialer, считая диалы и
// запоминая созданные соединения.
type trackingDialer struct {
	mu    sync.Mutex
	conns []*trackedConn
}

func (d *trackingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	tracked := &trackedConn{Conn: conn}
	d.mu.Lock()
	d.conns = append(d.conns, tracked)
	d.mu.Unlock()
	return tracked, nil
}

func (d *trackingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, io.ErrClosedPipe
}

func (d *trackingDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.conns)
}

func (d *trackingDialer) openCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, conn := range d.conns {
		if !conn.closed.Load() {
			n++
		}
	}
	return n
}

// waitOpenCount ждёт, пока число НЕзакрытых соединений не станет want:
// http2 ClientConn.Close добирается до net.Conn через пару горутин, даём до 3с.
func (d *trackingDialer) waitOpenCount(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if d.openCount() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("open connections = %d, want %d (pool did not close its conns)", d.openCount(), want)
}

// startH2Server поднимает httptest TLS-сервер с HTTP/2 (реальный сокет).
func startH2Server(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func insecureH2TLS(t *testing.T) tls.Config {
	t.Helper()
	cfg, err := tls.NewClient(context.Background(), logger.NOP(), "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		Insecure:   true,
		ALPN:       []string{"h2"},
	})
	if err != nil {
		t.Fatalf("build insecure h2 tls config: %v", err)
	}
	return cfg
}

func postOnce(t *testing.T, dc DialerClient, requestURL string) {
	t.Helper()
	body := strings.NewReader("ping")
	if err := dc.PostPacket(context.Background(), requestURL, body, int64(body.Len())); err != nil {
		t.Fatalf("PostPacket: %v", err)
	}
}

// TestDefaultDialerClientCloseH2 — уровень одного DialerClient'а: пул http2
// реально переиспользует соединение, Close закрывает его, следующий запрос
// (даже на том же клиенте — так in-flight горутины переживают Reset) диалит
// НОВОЕ соединение, а не мёртвое из пула.
func TestDefaultDialerClientCloseH2(t *testing.T) {
	ts := startH2Server(t)
	dest := M.ParseSocksaddr(ts.Listener.Addr().String())
	dialer := &trackingDialer{}
	baseOptions := &option.V2RayXHTTPBaseOptions{Path: "/upload"}
	tlsConfig := insecureH2TLS(t)

	dc := createHTTPClient(dest, dialer, baseOptions, tlsConfig)
	ddc, isDefault := dc.(*DefaultDialerClient)
	if !isDefault {
		t.Fatalf("createHTTPClient returned %T, want *DefaultDialerClient", dc)
	}
	if ddc.httpVersion != "2" {
		t.Fatalf("httpVersion = %q, want \"2\" (test must exercise the h2 pool)", ddc.httpVersion)
	}
	requestURL, err := getBaseRequestURL(baseOptions, dest, tlsConfig)
	if err != nil {
		t.Fatalf("getBaseRequestURL: %v", err)
	}

	// Наполняем пул: два запроса, одно TCP-соединение.
	postOnce(t, dc, requestURL.String())
	postOnce(t, dc, requestURL.String())
	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("dials after two posts = %d, want 1 (h2 pool must reuse the conn)", got)
	}

	if err := ddc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !ddc.IsClosed() {
		t.Fatal("IsClosed() = false after Close (XmuxManager would keep handing this client out)")
	}
	// Соединение пула должно быть реально закрыто — это и есть фикс утечки
	// H2-сессий и мёртвого пула после сна.
	dialer.waitOpenCount(t, 0)

	// Следующий запрос обязан диалить заново (in-flight горутины со старым
	// клиентом самовосстанавливаются именно так до первой ротации).
	postOnce(t, dc, requestURL.String())
	if got := dialer.dialCount(); got != 2 {
		t.Fatalf("dials after post-Close post = %d, want 2 (must dial fresh, not reuse a dead conn)", got)
	}
}

// TestClientCloseResetsXmuxPoolH2 — верхний уровень (adapter.V2RayClientTransport,
// его и зовут vless/vmess/trojan из InterfaceUpdated): Close сбрасывает пул
// XmuxManager'а, закрывает соединения, и клиент остаётся рабочим — следующий
// GetXmuxClient выдаёт СВЕЖЕГО DialerClient'а, который успешно ходит в сеть
// новым TCP-соединением. Повторный Close не паникует.
func TestClientCloseResetsXmuxPoolH2(t *testing.T) {
	ts := startH2Server(t)
	dest := M.ParseSocksaddr(ts.Listener.Addr().String())
	dialer := &trackingDialer{}
	tlsConfig := insecureH2TLS(t)
	options := option.V2RayXHTTPOptions{
		Mode: "packet-up",
		V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
			Path: "/upload",
		},
	}

	transport, err := NewClient(context.Background(), dialer, dest, options, tlsConfig)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client := transport.(*Client)

	// Наполняем пул менеджера живым соединением по реальному сокету.
	requestURL, err := getBaseRequestURL(&options.V2RayXHTTPBaseOptions, dest, tlsConfig)
	if err != nil {
		t.Fatalf("getBaseRequestURL: %v", err)
	}
	dcBefore, _ := client.getHTTPClient()
	postOnce(t, dcBefore, requestURL.String())
	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("dials after warm-up = %d, want 1", got)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !dcBefore.IsClosed() {
		t.Fatal("old DialerClient not marked closed after Client.Close")
	}
	client.xmuxManager.mtx.Lock()
	poolLen := len(client.xmuxManager.xmuxClients)
	client.xmuxManager.mtx.Unlock()
	if poolLen != 0 {
		t.Fatalf("xmux pool size after Close = %d, want 0", poolLen)
	}
	dialer.waitOpenCount(t, 0)

	// 🔴 Критическая часть контракта: клиент ОСТАЁТСЯ РАБОЧИМ. Новый диал
	// обязан получить свежего DialerClient'а и успешно сходить в сеть.
	dcAfter, _ := client.getHTTPClient()
	if dcAfter == dcBefore {
		t.Fatal("getHTTPClient returned the closed client after Close")
	}
	if dcAfter.IsClosed() {
		t.Fatal("fresh DialerClient is already closed")
	}
	postOnce(t, dcAfter, requestURL.String())
	if got := dialer.dialCount(); got != 2 {
		t.Fatalf("dials after post-Close warm-up = %d, want 2 (fresh conn expected)", got)
	}

	// Reset, а не уничтожение: повторный Close тоже штатен.
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	dialer.waitOpenCount(t, 0)
}

// TestDefaultDialerClientCloseH1DrainsUploadPool — h1-путь: реальный пул там
// не http.Transport (у него DisableKeepAlives), а uploadRawPool с сырыми
// TCP-соединениями. Close обязан его дренировать и закрыть соединения; после
// Close следующий PostPacket диалит заново.
func TestDefaultDialerClientCloseH1DrainsUploadPool(t *testing.T) {
	// Сырой TCP-сервер: h1-аплоад пишет запросы в соединение и не ждёт ответа
	// (UnreadedResponsesCount нигде не инкрементится — известная особенность
	// порта), так что достаточно читать и выбрасывать.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, conn) }()
		}
	}()

	dest := M.ParseSocksaddr(listener.Addr().String())
	dialer := &trackingDialer{}
	baseOptions := &option.V2RayXHTTPBaseOptions{Path: "/upload"}

	dc := createHTTPClient(dest, dialer, baseOptions, nil) // tls=nil → httpVersion "1.1"
	ddc := dc.(*DefaultDialerClient)
	if ddc.httpVersion != "1.1" {
		t.Fatalf("httpVersion = %q, want \"1.1\"", ddc.httpVersion)
	}
	requestURL, err := getBaseRequestURL(baseOptions, dest, nil)
	if err != nil {
		t.Fatalf("getBaseRequestURL: %v", err)
	}

	// Контракт uploadRawPool детерминирован только БЕЗ -race: под гонко-детектором
	// sync.Pool.Put дропает элемент с вероятностью 1/4 (runtime, sync/pool.go),
	// поэтому и reuse (второй POST берёт из пула), и drain на Close (дропнутые
	// соединения оказываются вне пула и Close их не видит) становятся
	// недетерминированными. Это артефакт гонко-детектора, а не наш баг — под
	// -race проверку семантики пула пропускаем, оставляя её для обычного прогона
	// (CI гоняет пакет и без -race). См. race_on_test.go / race_off_test.go.
	if raceEnabled {
		t.Skip("uploadRawPool reuse/drain assertions are nondeterministic under -race (sync.Pool.Put drops 1/4)")
	}

	postOnce(t, dc, requestURL.String())
	postOnce(t, dc, requestURL.String())
	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("dials after two h1 posts = %d, want 1 (uploadRawPool must reuse the conn)", got)
	}

	if err := ddc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialer.waitOpenCount(t, 0)

	postOnce(t, dc, requestURL.String())
	if got := dialer.dialCount(); got != 2 {
		t.Fatalf("dials after post-Close h1 post = %d, want 2", got)
	}
}

// TestXmuxManagerResetLazyRecreate — Reset на пустом и наполненном менеджере:
// не паникует, чистит список, следующий GetXmuxClient лениво создаёт нового.
func TestXmuxManagerResetLazyRecreate(t *testing.T) {
	created := 0
	manager := NewXmuxManager(option.V2RayXHTTPXmuxOptions{}, func() XmuxConn {
		created++
		return &DefaultDialerClient{}
	})

	manager.Reset() // пустой — no-op

	first := manager.GetXmuxClient(context.Background())
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
	manager.Reset()
	if len(manager.xmuxClients) != 0 {
		t.Fatalf("pool size after Reset = %d, want 0", len(manager.xmuxClients))
	}
	if !first.XmuxConn.IsClosed() {
		t.Fatal("pooled conn not closed by Reset")
	}
	second := manager.GetXmuxClient(context.Background())
	if created != 2 {
		t.Fatalf("created = %d, want 2 (lazy recreate)", created)
	}
	if second == first {
		t.Fatal("GetXmuxClient returned the closed client after Reset")
	}
}
