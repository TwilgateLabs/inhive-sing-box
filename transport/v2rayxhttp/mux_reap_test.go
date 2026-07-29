package xhttp

// Тесты reaper'а зомби-xmux-соединений (InHive 2026-07-29, см. mux.go).
//
// Баг (upstream Xray, кандидат в PR к XTLS): prune в GetXmuxClient выкидывал
// протухшего клиента из пула БЕЗ Close — его http2.Transport, горутины и
// uTLS-буферы жили дальше, пока их держал хоть один стрим (download-GET
// packet-up живёт всю жизнь проксируемого conn — часы/сутки). Device-repro
// требует ~255ч аптайма и недоступен, поэтому контракт reaper'а закрывается
// юнитами: свободного — закрыть сразу, занятого — в retired до освобождения,
// двойного Close не бывает, Reset закрывает всё, счётчики видят хвост.

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/option"
)

// reapConn — XmuxConn со счётчиком Close: единственный способ доказать и сам
// факт закрытия, и отсутствие двойного.
type reapConn struct {
	closed     atomic.Bool
	closeCalls atomic.Int32
}

func (c *reapConn) IsClosed() bool { return c.closed.Load() }

func (c *reapConn) Close() error {
	c.closed.Store(true)
	c.closeCalls.Add(1)
	return nil
}

func newReapManager() *XmuxManager {
	return NewXmuxManager(option.V2RayXHTTPXmuxOptions{}, func() XmuxConn {
		return &reapConn{}
	})
}

// expireForClose делает клиента протухшим И выводит его из handout-grace
// (в проде это «выдан давно, UnreusableAt истёк полчаса как»).
func expireForClose(m *XmuxManager, c *XmuxClient) {
	m.mtx.Lock()
	c.UnreusableAt = time.Now().Add(-time.Second)
	c.handedOutAt = time.Now().Add(-time.Minute)
	m.mtx.Unlock()
}

func retiredLen(m *XmuxManager) int {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return len(m.retired)
}

// TestXmuxPruneClosesIdleClient — prune клиента без стримов и POST'ов: Close
// вызывается сразу, в retired он не попадает.
func TestXmuxPruneClosesIdleClient(t *testing.T) {
	manager := newReapManager()
	first := manager.GetXmuxClient(context.Background())
	conn := first.XmuxConn.(*reapConn)
	expireForClose(manager, first)

	second := manager.GetXmuxClient(context.Background())
	if second == first {
		t.Fatal("expired client handed out again")
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("closeCalls = %d, want 1 (idle pruned client must be closed immediately)", got)
	}
	if got := retiredLen(manager); got != 0 {
		t.Fatalf("retired len = %d, want 0 (idle client must not be parked)", got)
	}
}

// TestXmuxPruneRetiresBusyClient — prune клиента с открытым стримом
// (OpenUsage>0): НЕ закрывается, паркуется в retired; после освобождения
// следующий GetXmuxClient его закрывает; повторные prune/sweep не дают
// двойного Close.
func TestXmuxPruneRetiresBusyClient(t *testing.T) {
	manager := newReapManager()
	first := manager.GetXmuxClient(context.Background())
	conn := first.XmuxConn.(*reapConn)
	first.OpenUsage.Add(1) // проксируемый conn держит клиента
	expireForClose(manager, first)

	_ = manager.GetXmuxClient(context.Background()) // prune → retired
	if got := conn.closeCalls.Load(); got != 0 {
		t.Fatalf("closeCalls = %d, want 0 (busy client must not be closed under an active stream)", got)
	}
	if got := retiredLen(manager); got != 1 {
		t.Fatalf("retired len = %d, want 1", got)
	}

	// Ещё занят — sweep на очередном Get обязан его НЕ тронуть.
	_ = manager.GetXmuxClient(context.Background())
	if got := conn.closeCalls.Load(); got != 0 {
		t.Fatalf("closeCalls = %d, want 0 (sweep closed a client with OpenUsage>0)", got)
	}

	// Стрим закрылся → следующий Get подметает.
	first.OpenUsage.Add(-1)
	_ = manager.GetXmuxClient(context.Background())
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("closeCalls = %d, want 1 (released retired client must be swept)", got)
	}
	if got := retiredLen(manager); got != 0 {
		t.Fatalf("retired len = %d, want 0 after sweep", got)
	}

	// Идемпотентность: дальнейшие Get/Sweep не закрывают второй раз.
	_ = manager.GetXmuxClient(context.Background())
	manager.SweepRetired()
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("closeCalls = %d, want 1 (double close)", got)
	}
}

// TestXmuxPruneRetiresClientWithInflightPost — летящий upload-POST (ротационный
// клиент, OpenUsage его не покрывает) тоже удерживает клиента от закрытия.
func TestXmuxPruneRetiresClientWithInflightPost(t *testing.T) {
	manager := newReapManager()
	first := manager.GetXmuxClient(context.Background())
	conn := first.XmuxConn.(*reapConn)
	first.inflightPosts.Add(1) // POST в полёте
	expireForClose(manager, first)

	_ = manager.GetXmuxClient(context.Background())
	if got := conn.closeCalls.Load(); got != 0 {
		t.Fatalf("closeCalls = %d, want 0 (client with in-flight POST must not be closed)", got)
	}
	if got := retiredLen(manager); got != 1 {
		t.Fatalf("retired len = %d, want 1", got)
	}

	first.inflightPosts.Add(-1)
	manager.SweepRetired() // путь onClose из client.go
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("closeCalls = %d, want 1 after POST landed", got)
	}
	if got := retiredLen(manager); got != 0 {
		t.Fatalf("retired len = %d, want 0 after sweep", got)
	}
}

// TestXmuxHandoutGraceDefersClose — гонка «выдан, но ещё не посчитан»: клиент,
// выданный только что (handedOutAt свежий), НЕ закрывается даже при нулевых
// счётчиках — вызывающий мог ещё не успеть сделать OpenUsage.Add(1).
func TestXmuxHandoutGraceDefersClose(t *testing.T) {
	manager := newReapManager()
	first := manager.GetXmuxClient(context.Background()) // handedOutAt = сейчас
	conn := first.XmuxConn.(*reapConn)
	manager.mtx.Lock()
	first.UnreusableAt = time.Now().Add(-time.Second) // протух, но выдан только что
	manager.mtx.Unlock()

	_ = manager.GetXmuxClient(context.Background())
	if got := conn.closeCalls.Load(); got != 0 {
		t.Fatalf("closeCalls = %d, want 0 (grace after handout must defer close)", got)
	}
	if got := retiredLen(manager); got != 1 {
		t.Fatalf("retired len = %d, want 1 (deferred into retired)", got)
	}

	// Grace истёк (за пределами окна выдачи) → sweep закрывает.
	manager.mtx.Lock()
	first.handedOutAt = time.Now().Add(-time.Minute)
	manager.mtx.Unlock()
	manager.SweepRetired()
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("closeCalls = %d, want 1 after grace elapsed", got)
	}
}

// TestXmuxResetClosesRetiredToo — Reset закрывает И пул, И retired-хвост
// (сеть сменилась — ждать освобождения стримов бессмысленно), без двойного
// Close при последующих Get/Sweep.
func TestXmuxResetClosesRetiredToo(t *testing.T) {
	manager := newReapManager()
	first := manager.GetXmuxClient(context.Background())
	firstConn := first.XmuxConn.(*reapConn)
	first.OpenUsage.Add(1)
	expireForClose(manager, first)
	second := manager.GetXmuxClient(context.Background()) // first → retired
	secondConn := second.XmuxConn.(*reapConn)
	if got := retiredLen(manager); got != 1 {
		t.Fatalf("retired len = %d, want 1 before Reset", got)
	}

	manager.Reset()
	if got := firstConn.closeCalls.Load(); got != 1 {
		t.Fatalf("retired conn closeCalls = %d, want 1 (Reset must close retired too)", got)
	}
	if got := secondConn.closeCalls.Load(); got != 1 {
		t.Fatalf("pooled conn closeCalls = %d, want 1", got)
	}
	if got := retiredLen(manager); got != 0 {
		t.Fatalf("retired len = %d, want 0 after Reset", got)
	}

	first.OpenUsage.Add(-1)
	_ = manager.GetXmuxClient(context.Background())
	manager.SweepRetired()
	if got := firstConn.closeCalls.Load(); got != 1 {
		t.Fatalf("retired conn closeCalls = %d, want 1 (double close after Reset)", got)
	}
}

// TestXmuxRetiredCounters — наблюдаемость: gauge retired растёт при парковке,
// падает при sweep; reaped растёт на каждый reaper-Close; XmuxState отдаёт оба.
// Счётчики глобальные (общие для всех менеджеров процесса), поэтому проверяем
// ДЕЛЬТЫ от снятого до теста среза.
func TestXmuxRetiredCounters(t *testing.T) {
	retiredBefore := xmuxRetiredGauge.Load()
	reapedBefore := xmuxReaped.Load()

	manager := newReapManager()
	first := manager.GetXmuxClient(context.Background())
	first.OpenUsage.Add(1)
	expireForClose(manager, first)
	_ = manager.GetXmuxClient(context.Background()) // prune → retired
	if got := xmuxRetiredGauge.Load() - retiredBefore; got != 1 {
		t.Fatalf("retired gauge delta = %d, want 1", got)
	}

	first.OpenUsage.Add(-1)
	manager.SweepRetired()
	if got := xmuxRetiredGauge.Load() - retiredBefore; got != 0 {
		t.Fatalf("retired gauge delta = %d, want 0 after sweep", got)
	}
	if got := xmuxReaped.Load() - reapedBefore; got != 1 {
		t.Fatalf("reaped delta = %d, want 1 after sweep", got)
	}

	// Прямой prune-Close (без парковки) тоже учитывается в reaped.
	second := manager.GetXmuxClient(context.Background())
	expireForClose(manager, second)
	_ = manager.GetXmuxClient(context.Background())
	if got := xmuxReaped.Load() - reapedBefore; got != 2 {
		t.Fatalf("reaped delta = %d, want 2 after direct prune close", got)
	}

	state := XmuxState()
	if !strings.Contains(state, " retired=") || !strings.Contains(state, " reaped=") {
		t.Fatalf("XmuxState() = %q, want retired=/reaped= fields", state)
	}
}

// TestXmuxReapStress — конкурентные Get/Sweep/Reset под -race: инварианты —
// ни одного двойного Close и полная зачистка после финального Reset.
// cMaxReuseTimes=1..1 даёт максимальный churn (каждый клиент одноразовый),
// grace ужимается до нуля, чтобы прогнать и ветку немедленного Close.
func TestXmuxReapStress(t *testing.T) {
	oldGrace := xmuxHandoutCloseGrace
	xmuxHandoutCloseGrace = 0
	t.Cleanup(func() { xmuxHandoutCloseGrace = oldGrace })

	var conns sync.Map // *reapConn → struct{}
	manager := NewXmuxManager(option.V2RayXHTTPXmuxOptions{
		CMaxReuseTimes: Xbadoption.Range{From: 1, To: 1},
	}, func() XmuxConn {
		conn := &reapConn{}
		conns.Store(conn, struct{}{})
		return conn
	})

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				client := manager.GetXmuxClient(context.Background())
				client.OpenUsage.Add(1)
				client.inflightPosts.Add(1)
				client.inflightPosts.Add(-1)
				client.OpenUsage.Add(-1)
				manager.SweepRetired()
				if seed == 0 && i%50 == 0 {
					manager.Reset()
				}
			}
		}(g)
	}
	wg.Wait()
	manager.Reset()

	conns.Range(func(key, _ any) bool {
		conn := key.(*reapConn)
		if got := conn.closeCalls.Load(); got > 1 {
			t.Fatalf("closeCalls = %d, want <=1 (double close under concurrency)", got)
		}
		if !conn.IsClosed() {
			t.Fatal("conn left open after final Reset (leak)")
		}
		return true
	})
	if got := retiredLen(manager); got != 0 {
		t.Fatalf("retired len = %d, want 0 after final Reset", got)
	}
}
