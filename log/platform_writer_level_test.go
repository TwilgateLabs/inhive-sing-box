package log

import (
	"bytes"
	"context"
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
