package route

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// recordingLogger — захват строк для проверки, что переходы дегрейда реально
// логируются (наблюдаемость, инцидент 2026-08-10: ноль следов брейкера в
// диагностике). Пишем только Warn*: переходы обязаны логироваться на WARN —
// дефолтный log level клиента 'warn', ниже до box.log не доедет.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) record(args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprint(args...))
	l.mu.Unlock()
}

func (l *recordingLogger) warnLines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *recordingLogger) Trace(args ...any)                             {}
func (l *recordingLogger) Debug(args ...any)                             {}
func (l *recordingLogger) Info(args ...any)                              {}
func (l *recordingLogger) Warn(args ...any)                              { l.record(args...) }
func (l *recordingLogger) Error(args ...any)                             {}
func (l *recordingLogger) Fatal(args ...any)                             {}
func (l *recordingLogger) Panic(args ...any)                             {}
func (l *recordingLogger) TraceContext(ctx context.Context, args ...any) {}
func (l *recordingLogger) DebugContext(ctx context.Context, args ...any) {}
func (l *recordingLogger) InfoContext(ctx context.Context, args ...any)  {}
func (l *recordingLogger) WarnContext(ctx context.Context, args ...any)  { l.record(args...) }
func (l *recordingLogger) ErrorContext(ctx context.Context, args ...any) {}
func (l *recordingLogger) FatalContext(ctx context.Context, args ...any) {}
func (l *recordingLogger) PanicContext(ctx context.Context, args ...any) {}

func warnContaining(lines []string, substr string) int {
	var count int
	for _, line := range lines {
		if strings.Contains(line, substr) {
			count++
		}
	}
	return count
}

// stubOutbound — минимальный adapter.Outbound для прогона НАСТОЯЩЕГО
// NewConnection (не копии его логики): бюджет берётся/возвращается именно
// там, и утечка слота — главный риск правки, ловить её надо на реальном
// пути, включая ветки shed и dial-cap.
type stubOutbound struct {
	tag   string
	dials int
	dial  func(ctx context.Context) (net.Conn, error)
}

func (o *stubOutbound) Type() string           { return "stub" }
func (o *stubOutbound) Tag() string            { return o.tag }
func (o *stubOutbound) Network() []string      { return []string{N.NetworkTCP} }
func (o *stubOutbound) Dependencies() []string { return nil }
func (o *stubOutbound) DisplayType() string    { return "Stub" }
func (o *stubOutbound) IsReady() bool          { return true }

func (o *stubOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dials++
	return o.dial(ctx)
}

func (o *stubOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// Доменное назначение без DestinationAddresses → NewConnection идёт веткой
// this.DialContext, без DialSerialNetwork-обвязки.
func stubMetadata() adapter.InboundContext {
	return adapter.InboundContext{Destination: M.ParseSocksaddr("stub.invalid:80")}
}

// Переходы дегрейда обязаны быть видимы в логе (WARN): вход в дегрейд после
// порога подряд-фейлов, recovery со временем в дегрейде. Гоняем ТУ ЖЕ логику,
// что и NewConnection (updateHealthAfterDial вынесен ровно ради этого).
func TestUpdateHealthAfterDial_TransitionsAreLogged(t *testing.T) {
	log := &recordingLogger{}
	m := NewConnectionManager(log)
	h := m.outboundHealthFor("srv")
	ctx := context.Background()
	dialErr := context.DeadlineExceeded

	// До порога — тишина и не degraded.
	for i := 0; i < cbFailThreshold-1; i++ {
		m.updateHealthAfterDial(ctx, h, "srv", dialErr)
	}
	if h.degraded.Load() {
		t.Fatal("degraded до порога подряд-фейлов")
	}
	if m.IsOutboundDegraded("srv") {
		t.Fatal("IsOutboundDegraded=true до порога")
	}
	if len(log.warnLines()) != 0 {
		t.Fatalf("лог до дегрейда не пуст: %v", log.warnLines())
	}

	// Порог → дегрейд: флаг + ровно одна строка о переходе.
	m.updateHealthAfterDial(ctx, h, "srv", dialErr)
	if !h.degraded.Load() || !m.IsOutboundDegraded("srv") {
		t.Fatal("после порога outbound обязан быть degraded")
	}
	if got := warnContaining(log.warnLines(), "degraded after"); got != 1 {
		t.Fatalf("строк о входе в дегрейд: %d, ожидалась 1; лог: %v", got, log.warnLines())
	}

	// Дальнейшие фейлы degraded-outbound'а НЕ плодят строки о переходе.
	m.updateHealthAfterDial(ctx, h, "srv", dialErr)
	if got := warnContaining(log.warnLines(), "degraded after"); got != 1 {
		t.Fatalf("повторный фейл добавил строку о переходе; лог: %v", log.warnLines())
	}

	// Отмена юзером — не сигнал здоровья: состояние и лог не меняются.
	linesBefore := len(log.warnLines())
	m.updateHealthAfterDial(ctx, h, "srv", context.Canceled)
	if !h.degraded.Load() || len(log.warnLines()) != linesBefore {
		t.Fatal("context.Canceled повлиял на здоровье или лог")
	}

	// Успех → recovery МГНОВЕННО (никаких probe-окон): полный сброс + ровно
	// одна строка recovery.
	m.updateHealthAfterDial(ctx, h, "srv", nil)
	if h.degraded.Load() || m.IsOutboundDegraded("srv") || h.consecFails.Load() != 0 {
		t.Fatal("успех не сбросил дегрейд полностью")
	}
	if got := warnContaining(log.warnLines(), "recovered after"); got != 1 {
		t.Fatalf("строк о recovery: %d, ожидалась 1; лог: %v", got, log.warnLines())
	}

	// Повторный успех на живом outbound'е — тишина (переходов нет).
	linesBefore = len(log.warnLines())
	m.updateHealthAfterDial(ctx, h, "srv", nil)
	if len(log.warnLines()) != linesBefore {
		t.Fatalf("успех без перехода добавил строку: %v", log.warnLines())
	}
}

// IsOutboundDegraded по незнакомому тегу — false и НЕ создаёт health-запись.
func TestIsOutboundDegraded_UnknownTag(t *testing.T) {
	m := NewConnectionManager(&recordingLogger{})
	if m.IsOutboundDegraded("nonexistent") {
		t.Fatal("незнакомый тег считается degraded")
	}
	if _, loaded := m.health.Load("nonexistent"); loaded {
		t.Fatal("IsOutboundDegraded создал health-запись — обязан быть read-only")
	}
}

// Семантика бюджета: вне дегрейда слот даётся всегда (одновременность капит
// глобальный dialSem); в дегрейде — только пока бюджет не насыщен; released
// слот снова доступен.
func TestTryAcquireSlot_BudgetSemantics(t *testing.T) {
	m := NewConnectionManager(&recordingLogger{})
	h := m.outboundHealthFor("srv")

	// Вне дегрейда бюджет не ограничивает даже при превышении.
	for i := 0; i < degradedDialBudget+5; i++ {
		if !h.tryAcquireSlot() {
			t.Fatalf("здоровый outbound получил отказ слота на %d-м дайле", i+1)
		}
	}
	// Вход в дегрейд при уже перебранном бюджете: новых слотов нет — висящие
	// до дегрейда дайлы тоже пинят треды и считаются в бюджет.
	h.degraded.Store(true)
	if h.tryAcquireSlot() {
		t.Fatal("degraded при inFlight>бюджета выдал слот")
	}
	// Дренаж ниже бюджета → слоты снова выдаются.
	for i := 0; i < 6; i++ {
		h.releaseSlot()
	}
	if !h.tryAcquireSlot() {
		t.Fatal("degraded с свободным бюджетом отказал в слоте")
	}
	h.releaseSlot()
	for i := 0; i < degradedDialBudget-1; i++ {
		h.releaseSlot()
	}
	if got := h.inFlight.Load(); got != 0 {
		t.Fatalf("парность acquire/release нарушена: inFlight=%d, ожидался 0", got)
	}
}

// Дегрейд НЕ отшивает дайлы, пока бюджет не насыщен: дайл degraded-outbound'а
// идёт полным путём (реальный вызов DialContext), а слот бюджета возвращается
// после фейла.
func TestNewConnection_DegradedDialsFullPathWhileBudgetFree(t *testing.T) {
	log := &recordingLogger{}
	m := NewConnectionManager(log)
	h := m.outboundHealthFor("srv")
	h.degraded.Store(true)
	failsBefore := h.consecFails.Load()

	out := &stubOutbound{tag: "srv", dial: func(ctx context.Context) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	m.NewConnection(context.Background(), out, c1, stubMetadata(), nil)

	if out.dials != 1 {
		t.Fatalf("degraded-outbound со свободным бюджетом обязан дайлить: dials=%d", out.dials)
	}
	if got := h.inFlight.Load(); got != 0 {
		t.Fatalf("слот бюджета утёк на пути dial-фейла: inFlight=%d", got)
	}
	if got := h.consecFails.Load(); got != failsBefore+1 {
		t.Fatalf("фейл дайла не учёлся: consecFails=%d", got)
	}
	if got := warnContaining(log.warnLines(), "budget saturated"); got != 0 {
		t.Fatalf("shed-строка при свободном бюджете: %v", log.warnLines())
	}
}

// Насыщенный бюджет degraded-outbound'а → shed: дайл НЕ идёт (DialContext не
// зовётся), flow закрывается, rate-limited строка в WARN, чужой слот не
// возвращается (shed слота не занимал).
func TestNewConnection_ShedWhenBudgetSaturated(t *testing.T) {
	log := &recordingLogger{}
	m := NewConnectionManager(log)
	h := m.outboundHealthFor("srv")
	h.degraded.Store(true)
	h.inFlight.Store(degradedDialBudget) // бюджет выбран висящими дайлами
	defer h.inFlight.Store(0)

	out := &stubOutbound{tag: "srv", dial: func(ctx context.Context) (net.Conn, error) {
		t.Error("DialContext вызван при насыщенном бюджете")
		return nil, os.ErrInvalid
	}}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	m.NewConnection(context.Background(), out, c1, stubMetadata(), nil)

	if out.dials != 0 {
		t.Fatalf("shed-путь дайлил: dials=%d", out.dials)
	}
	if got := h.inFlight.Load(); got != degradedDialBudget {
		t.Fatalf("shed изменил inFlight: %d, ожидался %d", got, degradedDialBudget)
	}
	if got := warnContaining(log.warnLines(), "dial budget saturated"); got != 1 {
		t.Fatalf("строк о shed: %d, ожидалась 1; лог: %v", got, log.warnLines())
	}
}

// Главный риск правки: слот бюджета ОБЯЗАН вернуться, когда глобальный
// dialSem насыщен (tryAcquireDial()==false) — иначе бюджет утекает по одному
// слоту на каждый такой дроп, и outbound залипает в shed навсегда.
func TestNewConnection_BudgetSlotReleasedWhenDialSemSaturated(t *testing.T) {
	log := &recordingLogger{}
	m := NewConnectionManager(log)
	h := m.outboundHealthFor("srv")

	// Насыщаем глобальный семафор (package-scope; тесты в пакете идут
	// последовательно, параллельных пользователей нет).
	for i := 0; i < maxConcurrentDials; i++ {
		dialSem <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxConcurrentDials; i++ {
			<-dialSem
		}
	}()

	out := &stubOutbound{tag: "srv", dial: func(ctx context.Context) (net.Conn, error) {
		t.Error("DialContext вызван при насыщенном dialSem")
		return nil, os.ErrInvalid
	}}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	m.NewConnection(context.Background(), out, c1, stubMetadata(), nil)

	if got := h.inFlight.Load(); got != 0 {
		t.Fatalf("слот бюджета утёк на ветке dial-cap: inFlight=%d", got)
	}
	if got := warnContaining(log.warnLines(), "overloaded"); got != 1 {
		t.Fatalf("строк о dial-cap: %d, ожидалась 1; лог: %v", got, log.warnLines())
	}
	// Дроп по dial-cap — не сигнал здоровья outbound'а: дайл даже не начинался.
	if got := h.consecFails.Load(); got != 0 {
		t.Fatalf("дроп по dial-cap учёлся как фейл дайла: consecFails=%d", got)
	}
}

// Успешный дайл снимает дегрейд МГНОВЕННО — без всяких probe-окон: одна из
// попыток, идущих в рамках бюджета, ответила — и outbound здоров. Слот
// бюджета при этом возвращается и на успешном пути.
func TestNewConnection_SuccessClearsDegradedImmediately(t *testing.T) {
	log := &recordingLogger{}
	m := NewConnectionManager(log)
	h := m.outboundHealthFor("srv")
	h.degraded.Store(true)
	h.consecFails.Store(cbFailThreshold + 3)

	remoteA, remoteB := net.Pipe()
	defer remoteA.Close()
	defer remoteB.Close()
	out := &stubOutbound{tag: "srv", dial: func(ctx context.Context) (net.Conn, error) {
		return remoteA, nil
	}}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	m.NewConnection(context.Background(), out, c1, stubMetadata(), nil)

	if h.degraded.Load() || m.IsOutboundDegraded("srv") {
		t.Fatal("успешный дайл не снял дегрейд мгновенно")
	}
	if got := h.consecFails.Load(); got != 0 {
		t.Fatalf("успех не сбросил consecFails: %d", got)
	}
	if got := h.inFlight.Load(); got != 0 {
		t.Fatalf("слот бюджета утёк на успешном пути: inFlight=%d", got)
	}
	if got := warnContaining(log.warnLines(), "recovered after"); got != 1 {
		t.Fatalf("строк о recovery: %d, ожидалась 1; лог: %v", got, log.warnLines())
	}
}

// ResetHealth (смена сети) НЕ снимает дегрейд и НЕ сбрасывает счётчик фейлов.
// Обнуление здесь выглядит «очевидным» («здоровье меряется на конкретной
// сети»), но при флапе интерфейса ResetNetwork приходит чаще, чем набирается
// порог 8 — дегрейд не наступал бы никогда, и шторм висящих дайлов (thread
// exhaustion на iOS, 2026-07-17) вернулся бы ровно в сценарии слабой сети.
// Цена сохранения при бюджетной схеме мизерна: ложный дегрейд живёт до
// первого успешного дайла (~RTT). См. комментарий у ResetHealth, прежде чем
// «чинить» этот assert.
func TestResetHealth_KeepsDegradedAndConsecFails(t *testing.T) {
	m := NewConnectionManager(nil)
	h := m.outboundHealthFor("srv")
	h.degraded.Store(true)
	h.consecFails.Store(cbFailThreshold + 3)

	m.ResetHealth()

	if !h.degraded.Load() {
		t.Fatal("ResetHealth снял degraded — это право только успешного дайла")
	}
	if got := h.consecFails.Load(); got != cbFailThreshold+3 {
		t.Fatalf("consecFails после ResetHealth = %d, ожидался %d (сохранение)",
			got, cbFailThreshold+3)
	}
}
