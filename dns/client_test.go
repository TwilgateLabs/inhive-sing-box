package dns

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
)

// Тесты фикса инцидента 2026-08-10 («cache wait timeout» 10s на имя):
// single-flight-ждун обязан ждать не дольше остатка ЛИДЕРА, а не свои полные
// c.timeout, и обязан коротить по мёртвому (circuit-open) outbound'у, не
// вставая в очередь. Всё — чистая логика таймеров/состояний, без сети.

// stubDNSTransport — transport с управляемым Exchange. Embeds TransportAdapter,
// чтобы получить Tag()/DetourTag() ровно тем же путём, что боевые transports.
type stubDNSTransport struct {
	TransportAdapter
	exchangeCalls atomic.Int64
	exchange      func(ctx context.Context, message *dns.Msg) (*dns.Msg, error)
}

func (t *stubDNSTransport) Start(stage adapter.StartStage) error { return nil }
func (t *stubDNSTransport) Close() error                         { return nil }
func (t *stubDNSTransport) Reset()                               {}

func (t *stubDNSTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	t.exchangeCalls.Add(1)
	return t.exchange(ctx, message)
}

func newStubTransport(detour string, exchange func(ctx context.Context, message *dns.Msg) (*dns.Msg, error)) *stubDNSTransport {
	return &stubDNSTransport{
		TransportAdapter: NewTransportAdapterWithRemoteOptions("stub", "stub-dns", option.RemoteDNSServerOptions{
			RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
				DialerOptions: option.DialerOptions{Detour: detour},
			},
		}),
		exchange: exchange,
	}
}

// stubConnManager — минимальный adapter.ConnectionManager для проверки
// circuit-open-ветки; управляем только IsOutboundDown.
type stubConnManager struct {
	downTags map[string]*atomic.Bool
}

func (m *stubConnManager) Start(stage adapter.StartStage) error            { return nil }
func (m *stubConnManager) Close() error                                    { return nil }
func (m *stubConnManager) Count() int                                      { return 0 }
func (m *stubConnManager) CloseAll()                                       {}
func (m *stubConnManager) ResetHealth()                                    {}
func (m *stubConnManager) TrackConn(conn net.Conn) net.Conn                { return conn }
func (m *stubConnManager) TrackPacketConn(c net.PacketConn) net.PacketConn { return c }
func (m *stubConnManager) NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
}
func (m *stubConnManager) NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
}

func (m *stubConnManager) IsOutboundDown(tag string) bool {
	if v, ok := m.downTags[tag]; ok {
		return v.Load()
	}
	return false
}

// stubGroupOutbound — селектор-заглушка: Now() отдаёт выбранный inner-тег.
type stubGroupOutbound struct {
	tag string
	now string
}

func (o *stubGroupOutbound) Type() string           { return "selector" }
func (o *stubGroupOutbound) Tag() string            { return o.tag }
func (o *stubGroupOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *stubGroupOutbound) Dependencies() []string { return nil }
func (o *stubGroupOutbound) DisplayType() string    { return "Selector" }
func (o *stubGroupOutbound) IsReady() bool          { return true }
func (o *stubGroupOutbound) Now() string            { return o.now }
func (o *stubGroupOutbound) All() []string          { return []string{o.now} }
func (o *stubGroupOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (o *stubGroupOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type stubOutboundManager struct {
	outbounds map[string]adapter.Outbound
}

func (m *stubOutboundManager) Start(stage adapter.StartStage) error { return nil }
func (m *stubOutboundManager) Close() error                         { return nil }
func (m *stubOutboundManager) Outbounds() []adapter.Outbound        { return nil }
func (m *stubOutboundManager) Default() adapter.Outbound            { return nil }
func (m *stubOutboundManager) Remove(tag string) error              { return nil }
func (m *stubOutboundManager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

func (m *stubOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

func testQuery(name string) *dns.Msg {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return message
}

func testResponse(message *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(message)
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   message.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IPv4(93, 184, 216, 34),
	})
	return response
}

// waitForFlight — дождаться, пока лидер зарегистрирует single-flight запись
// (иначе «ждун» в тесте может сам стать лидером).
func waitForFlight(t *testing.T, client *Client, question dns.Question) *exchangeFlight {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if flight, loaded := client.cacheLock.Load(question); loaded {
			return flight
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("лидер не зарегистрировал single-flight запись за 2s")
	return nil
}

// Ждун, пришедший ВНУТРИ окна зависшего лидера, падает по дедлайну ЛИДЕРА
// (leaderStart + timeout), а не через свои полные timeout. Сценарий инцидента:
// transport висит дольше своего ctx (мёртвый туннель), лидер не закрывает
// cond — раньше каждый ждун жёг свои полные 10s.
func TestExchangeWaiterBoundedByLeaderDeadline(t *testing.T) {
	t.Parallel()
	const timeout = 600 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	transport := newStubTransport("", func(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
		<-release // висим, игнорируя ctx — как мёртвый туннельный transport
		return nil, context.DeadlineExceeded
	})
	client := NewClient(ClientOptions{Timeout: timeout})

	leaderStart := time.Now()
	go client.Exchange(context.Background(), transport, testQuery("example.org"), adapter.DNSQueryOptions{}, nil)
	waitForFlight(t, client, testQuery("example.org").Question[0])

	// Ждун приходит на середине окна лидера.
	time.Sleep(timeout / 2)
	waiterStart := time.Now()
	_, err := client.Exchange(context.Background(), transport, testQuery("example.org"), adapter.DNSQueryOptions{}, nil)
	waiterElapsed := time.Since(waiterStart)
	sinceLeader := time.Since(leaderStart)

	if err == nil || err.Error() != "cache wait timeout" {
		t.Fatalf("ожидался err «cache wait timeout», получено: %v", err)
	}
	// Старое поведение: ждун ждёт свои полные timeout (600ms). Новое: остаток
	// лидера (~300ms). Порог с запасом на scheduling: < 90% собственного timeout.
	if waiterElapsed >= timeout*9/10 {
		t.Fatalf("ждун прождал %v — это его собственный полный timeout (%v), а не остаток лидера", waiterElapsed, timeout)
	}
	// И упал он около дедлайна лидера, не сильно раньше.
	if sinceLeader < timeout*2/3 {
		t.Fatalf("ждун упал через %v после старта лидера — раньше лидерского дедлайна %v", sinceLeader, timeout)
	}
}

// Ждун, пришедший ПОСЛЕ дедлайна зависшего лидера, падает сразу (remain<=0),
// а не встаёт в очередь ещё на timeout.
func TestExchangeWaiterAfterLeaderDeadlineFailsImmediately(t *testing.T) {
	t.Parallel()
	const timeout = 200 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	transport := newStubTransport("", func(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
		<-release
		return nil, context.DeadlineExceeded
	})
	client := NewClient(ClientOptions{Timeout: timeout})

	go client.Exchange(context.Background(), transport, testQuery("late.example.org"), adapter.DNSQueryOptions{}, nil)
	waitForFlight(t, client, testQuery("late.example.org").Question[0])

	time.Sleep(timeout + 100*time.Millisecond) // дедлайн лидера прошёл
	waiterStart := time.Now()
	_, err := client.Exchange(context.Background(), transport, testQuery("late.example.org"), adapter.DNSQueryOptions{}, nil)
	waiterElapsed := time.Since(waiterStart)

	if err == nil || err.Error() != "cache wait timeout" {
		t.Fatalf("ожидался err «cache wait timeout», получено: %v", err)
	}
	if waiterElapsed > 100*time.Millisecond {
		t.Fatalf("ждун после дедлайна лидера прождал %v вместо мгновенного фейла", waiterElapsed)
	}
}

// Семантика кеша сохранена: при успехе лидера ждун получает кешированный ответ,
// второй поход в transport не делается.
func TestExchangeWaiterGetsCachedResponseOnLeaderSuccess(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	transport := newStubTransport("", func(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
		<-release // лидер «резолвит» после того, как ждун встал в очередь
		return testResponse(message), nil
	})
	client := NewClient(ClientOptions{Timeout: 5 * time.Second})

	leaderDone := make(chan error, 1)
	go func() {
		_, err := client.Exchange(context.Background(), transport, testQuery("ok.example.org"), adapter.DNSQueryOptions{}, nil)
		leaderDone <- err
	}()
	waitForFlight(t, client, testQuery("ok.example.org").Question[0])

	waiterDone := make(chan error, 1)
	var waiterResponse *dns.Msg
	go func() {
		response, err := client.Exchange(context.Background(), transport, testQuery("ok.example.org"), adapter.DNSQueryOptions{}, nil)
		waiterResponse = response
		waiterDone <- err
	}()
	time.Sleep(50 * time.Millisecond) // ждун гарантированно в select
	close(release)

	if err := <-leaderDone; err != nil {
		t.Fatalf("лидер упал: %v", err)
	}
	if err := <-waiterDone; err != nil {
		t.Fatalf("ждун упал: %v", err)
	}
	if waiterResponse == nil || len(waiterResponse.Answer) != 1 {
		t.Fatalf("ждун не получил кешированный ответ: %v", waiterResponse)
	}
	if calls := transport.exchangeCalls.Load(); calls != 1 {
		t.Fatalf("transport.Exchange вызван %d раз, ожидался 1 (ждун обязан взять из кеша)", calls)
	}
}

// Отмена ctx ждуна возвращает ctx.Err(), а не подвешивает его.
func TestExchangeWaiterCtxCancel(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	transport := newStubTransport("", func(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
		<-release
		return nil, context.DeadlineExceeded
	})
	client := NewClient(ClientOptions{Timeout: 5 * time.Second})

	go client.Exchange(context.Background(), transport, testQuery("cancel.example.org"), adapter.DNSQueryOptions{}, nil)
	waitForFlight(t, client, testQuery("cancel.example.org").Question[0])

	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := client.Exchange(ctx, transport, testQuery("cancel.example.org"), adapter.DNSQueryOptions{}, nil)
		waiterDone <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-waiterDone:
		if err != context.Canceled {
			t.Fatalf("ожидался context.Canceled, получено: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ждун не вернулся после отмены ctx")
	}
}

// Circuit-open: transport с detour на down-outbound фейлит сразу, transport
// не дёргается и в очередь никто не встаёт. При этом cache-hit при
// down-сервере ОБЯЗАН отдаваться из кеша.
func TestExchangeCircuitOpenFastFail(t *testing.T) {
	t.Parallel()
	var down atomic.Bool
	manager := &stubConnManager{downTags: map[string]*atomic.Bool{"proxy": &down}}
	ctx := service.ContextWith[adapter.ConnectionManager](context.Background(), manager)

	transport := newStubTransport("proxy", func(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
		return testResponse(message), nil
	})
	client := NewClient(ClientOptions{Timeout: time.Second})

	// 1. Пока outbound жив — обычный успешный exchange (и наполняет кеш).
	if _, err := client.Exchange(ctx, transport, testQuery("cb.example.org"), adapter.DNSQueryOptions{}, nil); err != nil {
		t.Fatalf("exchange при живом outbound упал: %v", err)
	}

	// 2. Outbound down + кеш есть → ответ из кеша, без похода в transport.
	down.Store(true)
	callsBefore := transport.exchangeCalls.Load()
	response, err := client.Exchange(ctx, transport, testQuery("cb.example.org"), adapter.DNSQueryOptions{}, nil)
	if err != nil || response == nil || len(response.Answer) != 1 {
		t.Fatalf("cache-hit при down-сервере обязан отдаваться: response=%v err=%v", response, err)
	}
	if transport.exchangeCalls.Load() != callsBefore {
		t.Fatal("cache-hit при down-сервере сходил в transport")
	}

	// 3. Outbound down + кеша нет → мгновенный circuit-open fast-fail лидера.
	start := time.Now()
	_, err = client.Exchange(ctx, transport, testQuery("cb-miss.example.org"), adapter.DNSQueryOptions{}, nil)
	if err == nil {
		t.Fatal("ожидался circuit-open fast-fail")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("fast-fail занял %v вместо мгновенного", elapsed)
	}
	if transport.exchangeCalls.Load() != callsBefore {
		t.Fatal("circuit-open лидер сходил в transport")
	}
}

// В боевом конфиге detour DNS-сервера указывает на СЕЛЕКТОР ('select'), а
// брейкер ключует здоровье по тегу выбранного inner-outbound'а (Selector
// делегирует в NewConnection уже selected). Проверка обязана разворачивать
// группу через Now() — иначе не сработала бы никогда.
func TestExchangeCircuitOpenUnwrapsSelector(t *testing.T) {
	t.Parallel()
	var down atomic.Bool
	down.Store(true)
	manager := &stubConnManager{downTags: map[string]*atomic.Bool{"nl-1": &down}}
	ctx := service.ContextWith[adapter.ConnectionManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &stubOutboundManager{outbounds: map[string]adapter.Outbound{
		"select": &stubGroupOutbound{tag: "select", now: "nl-1"},
	}})

	transport := newStubTransport("select", func(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
		return testResponse(message), nil
	})
	client := NewClient(ClientOptions{Timeout: time.Second})

	_, err := client.Exchange(ctx, transport, testQuery("unwrap.example.org"), adapter.DNSQueryOptions{}, nil)
	if err == nil {
		t.Fatal("down выбранного inner-outbound'а селектора обязан давать circuit-open fast-fail")
	}
	if calls := transport.exchangeCalls.Load(); calls != 0 {
		t.Fatalf("transport.Exchange вызван %d раз при down inner-outbound'е", calls)
	}

	// Селектор переключили на живой сервер → запросы снова идут.
	down.Store(false)
	if _, err := client.Exchange(ctx, transport, testQuery("unwrap.example.org"), adapter.DNSQueryOptions{}, nil); err != nil {
		t.Fatalf("exchange после recovery упал: %v", err)
	}
}

// Circuit-open для ЖДУНА: лидер завис, outbound помечается down — ждун
// фейлит сразу, не вставая в очередь на остаток лидера.
func TestExchangeCircuitOpenWaiterFastFail(t *testing.T) {
	t.Parallel()
	var down atomic.Bool
	manager := &stubConnManager{downTags: map[string]*atomic.Bool{"proxy": &down}}
	ctx := service.ContextWith[adapter.ConnectionManager](context.Background(), manager)

	release := make(chan struct{})
	defer close(release)
	transport := newStubTransport("proxy", func(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
		<-release
		return nil, context.DeadlineExceeded
	})
	client := NewClient(ClientOptions{Timeout: 5 * time.Second})

	go client.Exchange(ctx, transport, testQuery("cb-wait.example.org"), adapter.DNSQueryOptions{}, nil)
	waitForFlight(t, client, testQuery("cb-wait.example.org").Question[0])

	down.Store(true) // брейкер узнал о смерти outbound'а, пока лидер в полёте
	start := time.Now()
	_, err := client.Exchange(ctx, transport, testQuery("cb-wait.example.org"), adapter.DNSQueryOptions{}, nil)
	if err == nil {
		t.Fatal("ожидался circuit-open fast-fail ждуна")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("ждун при down-outbound прождал %v вместо мгновенного фейла", elapsed)
	}
}
