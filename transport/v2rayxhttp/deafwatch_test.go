package xhttp

// Тесты детектора «глухого download» (deafwatch.go). Device-repro недоступен
// (CDN idle-cut воспроизводится только на живом эдже), поэтому юнит-покрытие —
// единственная верификация логики: условие срабатывания, однократность на
// эпизод, сброс при возобновлении downlink, защита законных idle-сессий,
// неактивность вне packet-up (nil-safe no-op).

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingLogger — минимальный logger.ContextLogger, копящий Warn-строки.
type recordingLogger struct {
	mtx   sync.Mutex
	lines []string
}

func (l *recordingLogger) record(args []any) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	var sb strings.Builder
	for _, arg := range args {
		if s, ok := arg.(string); ok {
			sb.WriteString(s)
		}
	}
	l.lines = append(l.lines, sb.String())
}

func (l *recordingLogger) warns() []string {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *recordingLogger) Trace(args ...any) {}
func (l *recordingLogger) Debug(args ...any) {}
func (l *recordingLogger) Info(args ...any)  {}
func (l *recordingLogger) Warn(args ...any)  { l.record(args) }
func (l *recordingLogger) Error(args ...any) {}
func (l *recordingLogger) Fatal(args ...any) {}
func (l *recordingLogger) Panic(args ...any) {}

func (l *recordingLogger) TraceContext(ctx context.Context, args ...any) {}
func (l *recordingLogger) DebugContext(ctx context.Context, args ...any) {}
func (l *recordingLogger) InfoContext(ctx context.Context, args ...any)  {}
func (l *recordingLogger) WarnContext(ctx context.Context, args ...any)  { l.record(args) }
func (l *recordingLogger) ErrorContext(ctx context.Context, args ...any) {}
func (l *recordingLogger) FatalContext(ctx context.Context, args ...any) {}
func (l *recordingLogger) PanicContext(ctx context.Context, args ...any) {}

// deafCounter — снимок глобального счётчика (тесты пакета гоняются вместе,
// поэтому все ассерты — по дельте).
func deafCounter() int64 { return xhttpSilentDL.Load() }

// makeDeaf выставляет детектору состояние «download молчит silence, uplink
// активен uploadAgo назад» относительно now.
func makeDeaf(w *deafWatch, now time.Time, silence, uploadAgo time.Duration) {
	w.lastDownlinkNano.Store(now.Add(-silence).UnixNano())
	w.lastUploadProgressNano.Store(now.Add(-uploadAgo).UnixNano())
}

// Глухой download при активном uplink → лог ровно ОДИН раз (повторные тики
// того же эпизода молчат), счётчик +1, формат строки — по контракту.
func TestDeafWatchFiresOnceOnSilentDownload(t *testing.T) {
	log := &recordingLogger{}
	w := newDeafWatch(log, "deadbeef")
	now := time.Now()
	makeDeaf(w, now, deafSilenceThreshold+3*time.Second, time.Second)
	before := deafCounter()

	if !w.check(context.Background(), now) {
		t.Fatal("check() = false, want fire: download silent beyond threshold with active uplink")
	}
	// Повторные тики того же эпизода — тишина.
	for i := 0; i < 3; i++ {
		if w.check(context.Background(), now.Add(time.Duration(i)*deafWatchTick)) {
			t.Fatal("check() fired again within the same episode, want once per episode")
		}
	}
	if got := deafCounter() - before; got != 1 {
		t.Fatalf("silentdl counter delta = %d, want 1", got)
	}
	warns := log.warns()
	if len(warns) != 1 {
		t.Fatalf("logged %d warn lines, want exactly 1: %v", len(warns), warns)
	}
	line := warns[0]
	for _, want := range []string{"[xhttp] download глух", "session=deadbeef", "last_downlink=", "last_upload_200=", "XTLS#6554"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line %q, want substring %q", line, want)
		}
	}
}

// Возобновление downlink сбрасывает эпизод: следующая тишина логируется снова.
func TestDeafWatchEpisodeResetOnDownlinkResume(t *testing.T) {
	log := &recordingLogger{}
	w := newDeafWatch(log, "s")
	now := time.Now()
	before := deafCounter()

	makeDeaf(w, now, deafSilenceThreshold+time.Second, time.Second)
	if !w.check(context.Background(), now) {
		t.Fatal("first episode: check() = false, want fire")
	}
	// Downlink ожил → эпизод закрыт.
	w.noteDownlink()
	if w.check(context.Background(), time.Now()) {
		t.Fatal("check() fired right after downlink resumed, want silence")
	}
	// Новая тишина → новый эпизод → снова лог.
	now2 := time.Now()
	makeDeaf(w, now2, deafSilenceThreshold+2*time.Second, 2*time.Second)
	if !w.check(context.Background(), now2) {
		t.Fatal("second episode: check() = false, want fire after downlink resume reset")
	}
	if got := deafCounter() - before; got != 2 {
		t.Fatalf("silentdl counter delta = %d, want 2 (two episodes)", got)
	}
}

// Idle-both: uplink тоже молчит (long-poll, idle SSH, push) → НЕ логируем.
func TestDeafWatchQuietOnLegitimateIdle(t *testing.T) {
	log := &recordingLogger{}
	w := newDeafWatch(log, "s")
	now := time.Now()
	before := deafCounter()

	// Uplink «был давно» — за пределами окна активности.
	makeDeaf(w, now, deafSilenceThreshold+10*time.Second, deafUplinkActiveWindow+time.Second)
	if w.check(context.Background(), now) {
		t.Fatal("check() fired on idle-both session, want silence (uplink gate)")
	}
	// Uplink «не был никогда» (0) — сессия вообще ничего не слала.
	w.lastUploadProgressNano.Store(0)
	if w.check(context.Background(), now) {
		t.Fatal("check() fired with zero upload progress ever, want silence")
	}
	if got := deafCounter() - before; got != 0 {
		t.Fatalf("silentdl counter delta = %d, want 0", got)
	}
	if len(log.warns()) != 0 {
		t.Fatalf("logged %v on legitimate idle, want nothing", log.warns())
	}
}

// Живой download → не логируем, даже при активном uplink.
func TestDeafWatchQuietOnHealthyDownlink(t *testing.T) {
	log := &recordingLogger{}
	w := newDeafWatch(log, "s")
	now := time.Now()
	before := deafCounter()

	makeDeaf(w, now, deafSilenceThreshold/2, time.Second)
	if w.check(context.Background(), now) {
		t.Fatal("check() fired with healthy downlink, want silence")
	}
	if got := deafCounter() - before; got != 0 {
		t.Fatalf("silentdl counter delta = %d, want 0", got)
	}
	if len(log.warns()) != 0 {
		t.Fatalf("logged %v with healthy downlink, want nothing", log.warns())
	}
}

// Не-packet-up: детектор не создаётся (dw == nil в DialContext), все вызовы —
// nil-safe no-op. Гейт по mode проверяется на уровне resolveXHTTPMode +
// конструкции в DialContext; здесь фиксируем контракт nil-безопасности,
// на который та конструкция опирается.
func TestDeafWatchNilSafeForNonPacketUp(t *testing.T) {
	var w *deafWatch
	// Не должно паниковать и не должно ничего считать.
	before := deafCounter()
	w.noteDownlink()
	w.noteUploadProgress()
	if got := deafCounter() - before; got != 0 {
		t.Fatalf("nil deafWatch touched the counter: delta = %d, want 0", got)
	}
}

// Интеграционный прогон watchdog-тикера с ужатыми порогами (паттерн
// xmuxHandoutCloseGrace): активный uplink + глухой download → run() сам ловит
// состояние и логирует один раз; отмена ctx останавливает горутину.
func TestDeafWatchRunLoop(t *testing.T) {
	oldSilence, oldWindow, oldTick := deafSilenceThreshold, deafUplinkActiveWindow, deafWatchTick
	deafSilenceThreshold = 60 * time.Millisecond
	deafUplinkActiveWindow = 500 * time.Millisecond
	deafWatchTick = 10 * time.Millisecond
	defer func() {
		deafSilenceThreshold, deafUplinkActiveWindow, deafWatchTick = oldSilence, oldWindow, oldTick
	}()

	log := &recordingLogger{}
	w := newDeafWatch(log, "s")
	before := deafCounter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stopped atomic.Bool
	go func() {
		w.run(ctx)
		stopped.Store(true)
	}()
	// Uplink активен, downlink молчит с рождения — run обязан поймать.
	w.noteUploadProgress()
	deadline := time.Now().Add(2 * time.Second)
	for deafCounter()-before == 0 && time.Now().Before(deadline) {
		w.noteUploadProgress() // держим uplink активным
		time.Sleep(5 * time.Millisecond)
	}
	if got := deafCounter() - before; got != 1 {
		t.Fatalf("run loop: silentdl counter delta = %d, want 1", got)
	}
	if len(log.warns()) != 1 {
		t.Fatalf("run loop logged %d lines, want 1: %v", len(log.warns()), log.warns())
	}
	cancel()
	deadline = time.Now().Add(2 * time.Second)
	for !stopped.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !stopped.Load() {
		t.Fatal("run() did not stop after ctx cancel")
	}
}

// deafReader двигает lastDownlink только на реальных байтах (n>0).
func TestDeafReaderMovesDownlinkOnRealBytesOnly(t *testing.T) {
	w := newDeafWatch(nil, "s")
	old := time.Now().Add(-time.Hour).UnixNano()
	w.lastDownlinkNano.Store(old)
	w.episodeLogged.Store(true)

	r := &deafReader{ReadCloser: readCloserFunc(func(b []byte) (int, error) { return 0, nil }), watch: w}
	_, _ = r.Read(make([]byte, 4))
	if w.lastDownlinkNano.Load() != old {
		t.Fatal("zero-byte read moved lastDownlink, want untouched")
	}
	if !w.episodeLogged.Load() {
		t.Fatal("zero-byte read reset the episode flag, want untouched")
	}

	r.ReadCloser = readCloserFunc(func(b []byte) (int, error) { return 3, nil })
	_, _ = r.Read(make([]byte, 4))
	if w.lastDownlinkNano.Load() == old {
		t.Fatal("real-byte read did not move lastDownlink")
	}
	if w.episodeLogged.Load() {
		t.Fatal("real-byte read did not reset the episode flag")
	}
}

type readCloserFunc func(b []byte) (int, error)

func (f readCloserFunc) Read(b []byte) (int, error) { return f(b) }
func (f readCloserFunc) Close() error               { return nil }
