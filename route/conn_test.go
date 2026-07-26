package route

import (
	"testing"
	"time"
)

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
