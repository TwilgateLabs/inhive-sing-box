package log

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
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
	startAccess       sync.Mutex
	started           atomic.Bool
	pendingEntries    []pendingEntry
}

type pendingEntry struct {
	ctx       context.Context
	level     Level
	tag       string
	message   string
	timestamp time.Time
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
	// InHive: upstream 9d8d4b879 копит строки в pendingEntries до Start() и
	// сливает их уже после — это чинит ровно один случай: filePath != "" и
	// writer до Start() равен io.Discard (log.New), т.е. запись в box.log
	// терялась. Отключаем буферизацию там, где она ничего не чинит, а только
	// ломает:
	//
	//   filePath == "" — writer финальный уже здесь, Start() для него no-op,
	//   копить нечего. Практика: hcore-фабрика (v2/hcore/grpc_server.go,
	//   static.CoreLogFactory) создаётся через log.New и Start() ей НИКТО не
	//   зовёт — с буферизацией вкладка «Логи» молча опустела бы, а
	//   pendingEntries рос бы без границы (mem_sampler пишет туда по тикам),
	//   что в iOS NE с memory-limit заканчивается убийством процесса.
	//
	// Инвариант InHive «платформенный путь (вкладка «Логи») не гейтится ничем —
	// ни уровнем фабрики, ни её состоянием» сохраняется НЕ отключением
	// буферизации, а доставкой в platformWriter прямо из буферизующей ветки
	// observableLogger.Log: строка уходит в UI сразу (даже если box.New()
	// упадёт и Start() не случится вовсе), а в box.log — при сливе в Start().
	// Слив идёт через outputWith(deliverPlatform=false), чтобы не задвоить.
	//
	// Гейт: log/platform_writer_level_test.go.
	if filePath == "" {
		factory.started.Store(true)
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
	var err error
	if f.filePath != "" {
		// InHive: ротация ДО открытия файла — иначе O_APPEND продолжит писать
		// в раздутый box.log (инцидент 2026-06-25).
		f.rotateIfOversized()
		logFile, openErr := filemanager.OpenFile(f.ctx, f.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if openErr != nil {
			err = openErr
		} else {
			f.writer = logFile
			f.file = logFile
		}
	}
	f.startAccess.Lock()
	pendingEntries := f.pendingEntries
	f.pendingEntries = nil
	f.started.Store(true)
	f.startAccess.Unlock()
	for _, entry := range pendingEntries {
		// InHive: deliverPlatform=false — в platformWriter эти строки уже ушли
		// в момент логирования (буферизующая ветка observableLogger.Log).
		f.outputWith(entry.ctx, entry.level, entry.tag, entry.message, entry.timestamp, false)
	}
	return err
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
	f.startAccess.Lock()
	f.pendingEntries = nil
	f.startAccess.Unlock()
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

func (f *defaultFactory) output(ctx context.Context, level Level, tag string, message string, timestamp time.Time) {
	f.outputWith(ctx, level, tag, message, timestamp, true)
}

// outputWith: deliverPlatform управляет ТОЛЬКО хвостовой доставкой в
// platformWriter. false ставит один вызов — слив pendingEntries в Start():
// эти строки уже доставлены в UI из буферизующей ветки observableLogger.Log,
// повторная доставка задвоила бы их на вкладке «Логи».
func (f *defaultFactory) outputWith(ctx context.Context, level Level, tag string, message string, timestamp time.Time, deliverPlatform bool) {
	if f.needObservable {
		formatted, formattedSimple := f.formatter.FormatWithSimple(ctx, level, tag, message, timestamp)
		if level <= f.level {
			if level == LevelPanic {
				panic(formatted)
			}
			f.writer.Write([]byte(formatted))
			if level == LevelFatal {
				os.Exit(1)
			}
		}
		f.subscriber.Emit(Entry{level, formattedSimple})
	} else if level <= f.level {
		formatted := f.formatter.Format(ctx, level, tag, message, timestamp)
		if level == LevelPanic {
			panic(formatted)
		}
		f.writer.Write([]byte(formatted))
		if level == LevelFatal {
			os.Exit(1)
		}
	}
	if deliverPlatform && f.platformWriter != nil {
		f.platformWriter.WriteMessage(level, f.platformFormatter.Format(ctx, level, tag, message, timestamp))
	}
}

var _ ContextLogger = (*observableLogger)(nil)

type observableLogger struct {
	*defaultFactory
	tag string
}

func (l *observableLogger) Log(ctx context.Context, level Level, args []any) {
	level = OverrideLevelFromContext(level, ctx)
	if level > l.level && l.platformWriter == nil && !l.needObservable {
		return
	}
	nowTime := time.Now()
	message := F.ToString(args...)
	if !l.started.Load() && level != LevelFatal && level != LevelPanic {
		l.startAccess.Lock()
		if !l.started.Load() {
			l.pendingEntries = append(l.pendingEntries, pendingEntry{ctx, level, l.tag, message, nowTime})
			l.startAccess.Unlock()
			// InHive: платформенный путь (вкладка «Логи») не ждёт Start().
			// box.New() логирует ДО preStart()/logFactory.Start() (лог линта
			// конфига, предупреждения о deprecated-опциях); если box.New()
			// упадёт, Start() не случится вовсе, и без этой доставки строки —
			// то самое, ради чего вкладку открывают, — исчезли бы бесследно.
			// В box.log они попадут при сливе pendingEntries в Start()
			// (outputWith с deliverPlatform=false — задвоения нет).
			if l.platformWriter != nil {
				l.platformWriter.WriteMessage(level, l.platformFormatter.Format(ctx, level, l.tag, message, nowTime))
			}
			return
		}
		l.startAccess.Unlock()
	}
	l.output(ctx, level, l.tag, message, nowTime)
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
