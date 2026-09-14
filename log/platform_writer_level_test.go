package log

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

type recordingPlatformWriter struct {
	got []Level
}

func (s *recordingPlatformWriter) WriteMessage(level Level, message string) {
	s.got = append(s.got, level)
}

func (s *recordingPlatformWriter) DisableColors() bool { return true }

// Нагрузочно-несущий инвариант InHive (зафиксирован 2026-07-21): PlatformWriter
// получает строки ВСЕХ уровней, В ОБХОД уровня фабрики. На этом стоит вкладка
// «Логи»: цепочка factory→PlatformWriter→StartedService→LogInterface→hcore.Log
// фильтруется ТОЛЬКО static.logLevel (переключаемым с вкладки), а не уровнем
// фабрики из конфига (warn). Если бамп sing-box вернёт уровневый гейт перед
// platformWriter — TRACE/DEBUG на вкладке молча перестанет показывать
// debug-строки движка. Этот тест сломается первым и назовёт причину.
func TestPlatformWriterReceivesAllLevels(t *testing.T) {
	stub := &recordingPlatformWriter{}
	factory, err := New(Options{
		Context:        context.Background(),
		Options:        option.LogOptions{Level: "warn"},
		Observable:     true,
		BaseTime:       time.Now(),
		PlatformWriter: stub,
	})
	if err != nil {
		t.Fatal(err)
	}
	logger := factory.Logger()
	logger.Debug("debug line")
	logger.Warn("warn line")
	if len(stub.got) != 2 {
		t.Fatalf("platform writer got %d messages (%v), want 2: уровень фабрики не должен резать platformWriter-путь", len(stub.got), stub.got)
	}
}

// Обратная сторона: файловый writer фабрики (box.log) уровнем РЕЖЕТСЯ, и
// SetLevel на живой фабрике реально открывает/закрывает ему debug-строки —
// на этом стоит пункт «TRACE/DEBUG поднимает уровень движка» вкладки «Логи»
// (hcore.ChangeInhiveSettings → applyLogLevelToLiveBox → SetLevel).
func TestSetLevelGatesFileWriterLive(t *testing.T) {
	var buf bytes.Buffer
	factory, err := New(Options{
		Context:       context.Background(),
		Options:       option.LogOptions{Level: "warn"},
		DefaultWriter: &buf,
		BaseTime:      time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	logger := factory.Logger()

	logger.Debug("hidden")
	if bytes.Contains(buf.Bytes(), []byte("hidden")) {
		t.Fatal("debug line written at level warn")
	}
	factory.SetLevel(LevelDebug)
	logger.Debug("visible")
	if !bytes.Contains(buf.Bytes(), []byte("visible")) {
		t.Fatal("debug line not written after live SetLevel(debug)")
	}
	factory.SetLevel(LevelWarn)
	logger.Debug("hidden-again")
	if bytes.Contains(buf.Bytes(), []byte("hidden-again")) {
		t.Fatal("debug line written after restore to warn")
	}
}

// InHive 2026-09-14 (merge v1.13.21): upstream 9d8d4b879 буферизует строки до
// logFactory.Start() ради box.log (до Start() writer == io.Discard). Файловая
// фабрика — это ПЕРВИЧНАЯ фабрика box'а (v2/config: LogFile="data/box.log",
// daemon/instance.go передаёт PlatformLogWriter), т.е. у неё есть И filePath,
// И platformWriter. Инвариант: буферизация файла НЕ должна задерживать
// платформенный путь — строки, залогированные из box.New() до Start(), обязаны
// быть на вкладке «Логи» немедленно (если box.New() упадёт, Start() не
// случится, и другого шанса нет), и ровно ОДИН раз — слив pendingEntries в
// Start() платформенный путь не повторяет.
func TestPlatformWriterReceivesBeforeStart(t *testing.T) {
	stub := &recordingPlatformWriter{}
	logPath := filepath.Join(t.TempDir(), "box.log")
	factory, err := New(Options{
		Context:        context.Background(),
		Options:        option.LogOptions{Level: "warn", Output: logPath},
		Observable:     true,
		BaseTime:       time.Now(),
		PlatformWriter: stub,
	})
	if err != nil {
		t.Fatal(err)
	}
	logger := factory.Logger()
	logger.Debug("pre-start debug line")
	logger.Warn("pre-start warn line")
	if len(stub.got) != 2 {
		t.Fatalf("platform writer got %d messages (%v) before Start, want 2: буферизация файла не должна гейтить платформенный путь", len(stub.got), stub.got)
	}
	if err = factory.Start(); err != nil {
		t.Fatal(err)
	}
	defer factory.Close()
	if len(stub.got) != 2 {
		t.Fatalf("platform writer got %d messages (%v) after Start, want 2: слив pendingEntries задвоил платформенный путь", len(stub.got), stub.got)
	}
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte("pre-start warn line")) {
		t.Fatal("pre-Start warn line missing from box.log: upstream 9d8d4b879 инертен")
	}
}
