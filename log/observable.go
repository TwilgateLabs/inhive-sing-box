package log

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service/filemanager"
)

var _ Factory = (*defaultFactory)(nil)

type defaultFactory struct {
	ctx               context.Context
	formatter         Formatter
	platformFormatter Formatter
	writer            io.Writer
	file              *os.File
	filePath          string
	platformWriter    PlatformWriter
	needObservable    bool
	level             Level
	subscriber        *observable.Subscriber[Entry]
	observer          *observable.Observer[Entry]
}

func NewDefaultFactory(
	ctx context.Context,
	formatter Formatter,
	writer io.Writer,
	filePath string,
	platformWriter PlatformWriter,
	needObservable bool,
) ObservableFactory {
	factory := &defaultFactory{
		ctx:       ctx,
		formatter: formatter,
		platformFormatter: Formatter{
			BaseTime:         formatter.BaseTime,
			DisableLineBreak: true,
			// InHive: platformWriter получает сообщения которые идут в UI через
			// gRPC stream (Flutter LogsPage). ANSI escape-коды для terminal'а
			// там только мусорят отображение ([36mINFO[0m вместо INFO).
			DisableColors: true,
		},
		writer:         writer,
		filePath:       filePath,
		platformWriter: platformWriter,
		needObservable: needObservable,
		level:          LevelTrace,
		subscriber:     observable.NewSubscriber[Entry](128),
	}
	/*if platformWriter != nil {
		factory.platformFormatter.DisableColors = platformWriter.DisableColors()
	}*/
	if needObservable {
		factory.observer = observable.NewObserver[Entry](factory.subscriber, 64)
	}
	return factory
}

// logRotateMaxBytes — порог ротации box.log. При старте, если файл больше
// этого размера, он переименовывается в <path>.1 (одна бэкап-копия,
// перезаписывая старую), затем открывается заново через O_APPEND. Без этого
// box.log рос бесконечно (в инциденте 2026-06-25 — 59MB накоплено с 11 мая) и
// каждая запись в горячем пути дёргала всё более раздутый файл. Ротация
// сделана вручную size-cap'ом, а НЕ через lumberjack: lumberjack не в
// зависимостях, а тащить новую dependency ради одного файла — лишний риск.
// Ротируем один раз при Start(): для VPN-туннеля сессия может жить часами, но
// гранулярности «обрезать при каждом подключении» достаточно, чтобы файл не
// уходил в десятки мегабайт.
const logRotateMaxBytes = 5 * 1024 * 1024

func (f *defaultFactory) Start() error {
	if f.filePath != "" {
		f.rotateIfOversized()
		logFile, err := filemanager.OpenFile(f.ctx, f.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		f.writer = logFile
		f.file = logFile
	}
	return nil
}

// rotateIfOversized переименовывает текущий лог в <path>.1 если он перерос
// logRotateMaxBytes. Все ошибки тут не фатальны — в худшем случае просто не
// ротируем и продолжаем писать в существующий файл (лог не должен ронять
// старт ядра). Пути резолвим через filemanager.BasePath, потому что filePath
// относительный (например data/box.log).
func (f *defaultFactory) rotateIfOversized() {
	path := filemanager.BasePath(f.ctx, f.filePath)
	info, err := os.Stat(path)
	if err != nil || info.Size() <= logRotateMaxBytes {
		return
	}
	backup := path + ".1"
	// Rename атомарно перетирает старый .1 (одна бэкап-копия по дизайну).
	_ = os.Rename(path, backup)
}

func (f *defaultFactory) Close() error {
	return common.Close(
		common.PtrOrNil(f.file),
		f.subscriber,
	)
}

func (f *defaultFactory) Level() Level {
	return f.level
}

func (f *defaultFactory) SetLevel(level Level) {
	f.level = level
}

func (f *defaultFactory) Logger() ContextLogger {
	return f.NewLogger("")
}

func (f *defaultFactory) NewLogger(tag string) ContextLogger {
	return &observableLogger{f, tag}
}

func (f *defaultFactory) Subscribe() (subscription observable.Subscription[Entry], done <-chan struct{}, err error) {
	return f.observer.Subscribe()
}

func (f *defaultFactory) UnSubscribe(sub observable.Subscription[Entry]) {
	f.observer.UnSubscribe(sub)
}

var _ ContextLogger = (*observableLogger)(nil)

type observableLogger struct {
	*defaultFactory
	tag string
}

func (l *observableLogger) Log(ctx context.Context, level Level, args []any) {
	level = OverrideLevelFromContext(level, ctx)
	if level > l.level && l.platformWriter == nil {
		return
	}
	nowTime := time.Now()
	if level <= l.level {
		if l.needObservable {
			message, messageSimple := l.formatter.FormatWithSimple(ctx, level, l.tag, F.ToString(args...), nowTime)
			if level == LevelPanic {
				panic(message)
			}
			l.writer.Write([]byte(message))
			if level == LevelFatal {
				os.Exit(1)
			}
			l.subscriber.Emit(Entry{level, messageSimple})
		} else {
			message := l.formatter.Format(ctx, level, l.tag, F.ToString(args...), nowTime)
			if level == LevelPanic {
				panic(message)
			}
			l.writer.Write([]byte(message))
			if level == LevelFatal {
				os.Exit(1)
			}
		}
	}
	if l.platformWriter != nil {
		l.platformWriter.WriteMessage(level, l.platformFormatter.Format(ctx, level, l.tag, F.ToString(args...), nowTime))
	}
}

func (l *observableLogger) Trace(args ...any) {
	l.TraceContext(context.Background(), args...)
}

func (l *observableLogger) Debug(args ...any) {
	l.DebugContext(context.Background(), args...)
}

func (l *observableLogger) Info(args ...any) {
	l.InfoContext(context.Background(), args...)
}

func (l *observableLogger) Warn(args ...any) {
	l.WarnContext(context.Background(), args...)
}

func (l *observableLogger) Error(args ...any) {
	l.ErrorContext(context.Background(), args...)
}

func (l *observableLogger) Fatal(args ...any) {
	l.FatalContext(context.Background(), args...)
}

func (l *observableLogger) Panic(args ...any) {
	l.PanicContext(context.Background(), args...)
}

func (l *observableLogger) TraceContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelTrace, args)
}

func (l *observableLogger) DebugContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelDebug, args)
}

func (l *observableLogger) InfoContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelInfo, args)
}

func (l *observableLogger) WarnContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelWarn, args)
}

func (l *observableLogger) ErrorContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelError, args)
}

func (l *observableLogger) FatalContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelFatal, args)
}

func (l *observableLogger) PanicContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelPanic, args)
}
