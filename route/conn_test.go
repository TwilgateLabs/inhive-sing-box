package route

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingLogger — захват строк для проверки, что переходы брейкера реально
// логируются (наблюдаемость, инцидент 2026-08-10: ноль следов брейкера в
// диагностике). Пишем только Warn*: брейкер обязан логировать на WARN —
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

// Переходы брейкера обязаны быть видимы в логе (WARN): trip после порога
// подряд-фейлов, probe-фейл с backoff'ом, recovery со временем down.
// Гоняем ТУ ЖЕ логику, что и NewConnection (updateHealthAfterDial вынесен
// ровно ради этого — по прецеденту tryClaimProbe).
func TestUpdateHealthAfterDial_TransitionsAreLogged(t *testing.T) {
	log := &recordingLogger{}
	m := NewConnectionManager(log)
	h := m.outboundHealthFor("srv")
	ctx := context.Background()
	dialErr := context.DeadlineExceeded

	// До порога — тишина и не down.
	for i := 0; i < cbFailThreshold-1; i++ {
		m.updateHealthAfterDial(ctx, h, "srv", false, dialErr)
	}
	if h.down.Load() {
		t.Fatal("down до порога подряд-фейлов")
	}
	if m.IsOutboundDown("srv") {
		t.Fatal("IsOutboundDown=true до trip'а")
	}
	if len(log.warnLines()) != 0 {
		t.Fatalf("лог до trip'а не пуст: %v", log.warnLines())
	}

	// Порог → trip: down + ровно одна строка о trip'е.
	m.updateHealthAfterDial(ctx, h, "srv", false, dialErr)
	if !h.down.Load() || !m.IsOutboundDown("srv") {
		t.Fatal("после порога outbound обязан быть down")
	}
	if got := warnContaining(log.warnLines(), "circuit-breaker: tripped"); got != 1 {
		t.Fatalf("строк о trip'е: %d, ожидалась 1; лог: %v", got, log.warnLines())
	}

	// Дальнейшие обычные фейлы down-outbound'а НЕ плодят trip-строки.
	m.updateHealthAfterDial(ctx, h, "srv", false, dialErr)
	if got := warnContaining(log.warnLines(), "circuit-breaker: tripped"); got != 1 {
		t.Fatalf("повторный фейл добавил trip-строку; лог: %v", log.warnLines())
	}

	// Probe-фейл: backoff ×2 + строка об исходе probe.
	intervalBefore := h.probeInterval.Load()
	m.updateHealthAfterDial(ctx, h, "srv", true, dialErr)
	if got := h.probeInterval.Load(); got != intervalBefore*2 {
		t.Fatalf("probe-фейл: interval %d, ожидался %d", got, intervalBefore*2)
	}
	if got := warnContaining(log.warnLines(), "probe failed"); got != 1 {
		t.Fatalf("строк о probe-фейле: %d, ожидалась 1; лог: %v", got, log.warnLines())
	}

	// Отмена юзером — не сигнал здоровья: состояние и лог не меняются.
	linesBefore := len(log.warnLines())
	m.updateHealthAfterDial(ctx, h, "srv", false, context.Canceled)
	if !h.down.Load() || len(log.warnLines()) != linesBefore {
		t.Fatal("context.Canceled повлиял на здоровье или лог")
	}

	// Успех → recovery: полный сброс + ровно одна строка recovery.
	m.updateHealthAfterDial(ctx, h, "srv", true, nil)
	if h.down.Load() || m.IsOutboundDown("srv") || h.consecFails.Load() != 0 || h.probeInterval.Load() != 0 {
		t.Fatal("успех не сбросил состояние брейкера полностью")
	}
	if got := warnContaining(log.warnLines(), "circuit-breaker: recovered"); got != 1 {
		t.Fatalf("строк о recovery: %d, ожидалась 1; лог: %v", got, log.warnLines())
	}

	// Повторный успех на живом outbound'е — тишина (переходов нет).
	linesBefore = len(log.warnLines())
	m.updateHealthAfterDial(ctx, h, "srv", false, nil)
	if len(log.warnLines()) != linesBefore {
		t.Fatalf("успех без перехода добавил строку: %v", log.warnLines())
	}
}

// IsOutboundDown по незнакомому тегу — false и НЕ создаёт health-запись.
func TestIsOutboundDown_UnknownTag(t *testing.T) {
	m := NewConnectionManager(&recordingLogger{})
	if m.IsOutboundDown("nonexistent") {
		t.Fatal("незнакомый тег считается down")
	}
	if _, loaded := m.health.Load("nonexistent"); loaded {
		t.Fatal("IsOutboundDown создал health-запись — обязан быть read-only")
	}
}

// Сценарий инцидента (аудит трубы 2026-07-26): сервер помечен down на старой
// сети, probe-backoff дополз до потолка 30с → юзер переключил Wi-Fi↔LTE, а
// брейкер ещё до полминуты fast-fail'ит дайлы на новой, рабочей сети.
// ResetNetwork теперь зовёт ResetHealth: probe-часы сбрасываются, ПЕРВЫЙ же
// дайл на новой сети идёт полным путём как probe. down при этом остаётся —
// его снимает только фактический успешный дайл (решение Никиты 2026-07-17:
// «здоровым» сервер объявляет только реальность, не смена сети).
func TestResetHealth_NextDialBecomesProbeImmediately(t *testing.T) {
	m := NewConnectionManager(nil)
	h := m.outboundHealthFor("srv")

	// Состояние как в бою после долгого blackhole: down, backoff у потолка,
	// последний probe — только что, счётчик за порогом.
	h.down.Store(true)
	h.consecFails.Store(cbFailThreshold + 3)
	h.probeInterval.Store(int64(cbProbeMax))
	h.lastProbe.Store(time.Now().UnixNano())

	// До сброса дайл обязан fast-fail'иться: backoff-окно (30с) не истекло.
	if h.tryClaimProbe(time.Now().UnixNano()) {
		t.Fatal("probe прошёл до истечения backoff-окна — гейт брейкера сломан")
	}

	m.ResetHealth()

	if !h.down.Load() {
		t.Fatal("ResetHealth снял down — это право только успешного дайла")
	}
	if got := h.probeInterval.Load(); got != 0 {
		t.Fatalf("probeInterval после ResetHealth = %d, ожидался 0", got)
	}
	if got := h.lastProbe.Load(); got != 0 {
		t.Fatalf("lastProbe после ResetHealth = %d, ожидался 0", got)
	}
	// consecFails ОБЯЗАН пережить сброс. Обнуление здесь выглядит «очевидным»
	// («здоровье меряется на конкретной сети»), но при флапе интерфейса
	// ResetNetwork приходит чаще, чем набирается порог 8 — брейкер не
	// сработал бы никогда, и шторм висящих дайлов (thread exhaustion на iOS,
	// 2026-07-17) вернулся бы ровно в сценарии слабой сети. См. комментарий
	// у ResetHealth, прежде чем «чинить» этот assert.
	if got := h.consecFails.Load(); got != cbFailThreshold+3 {
		t.Fatalf("consecFails после ResetHealth = %d, ожидался %d (сохранение)",
			got, cbFailThreshold+3)
	}

	// Первый дайл на новой сети — probe (interval==0 трактуется как база, а
	// lastProbe==0 делает окно заведомо истёкшим).
	if !h.tryClaimProbe(time.Now().UnixNano()) {
		t.Fatal("после ResetHealth первый дайл обязан идти probe'ом")
	}
	// Конкурентный дайл сразу следом — снова fast-fail: probe ровно один.
	if h.tryClaimProbe(time.Now().UnixNano()) {
		t.Fatal("второй дайл сразу после захваченного probe обязан fast-fail")
	}
}
