package monitoring

import (
	"context"
	"sync"
)

type Broadcaster[T any] struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu   sync.RWMutex
	subs map[chan T]struct{}
	once sync.Once

	// Кольцевая история для реплея поздним подписчикам (0 = выключена).
	// Нужна логам: без неё всё, что опубликовано до подписки UI (ошибки
	// старта ядра, ранний bring-up), терялось навсегда — особенно на iOS,
	// где приложение подписывается только после старта NE-процесса.
	historyCap int
	history    []T
}

func NewBroadcaster[T any](parent context.Context) *Broadcaster[T] {
	return NewBroadcasterWithHistory[T](parent, 0)
}

// NewBroadcasterWithHistory — брокастер, хранящий последние historyCap
// событий и отдающий их новым подписчикам через SubscribeWithReplay.
func NewBroadcasterWithHistory[T any](parent context.Context, historyCap int) *Broadcaster[T] {
	ctx, cancel := context.WithCancel(parent)
	b := &Broadcaster[T]{
		ctx:        ctx,
		cancel:     cancel,
		subs:       make(map[chan T]struct{}),
		historyCap: historyCap,
	}

	go b.watchContext()
	return b
}

func (b *Broadcaster[T]) watchContext() {
	<-b.ctx.Done()
	b.closeAll()
}

func (b *Broadcaster[T]) Subscribe(buffer int) <-chan T {
	ch := make(chan T, buffer)

	b.mu.Lock()
	defer b.mu.Unlock()

	select {
	case <-b.ctx.Done():
		close(ch)
	default:
		b.subs[ch] = struct{}{}
	}

	return ch
}

// SubscribeWithReplay — как Subscribe, но сначала кладёт в канал хвост
// истории (последние min(buffer, len(history)) событий), затем регистрирует
// подписчика. Всё под одним локом с Publish — на стыке ничего не теряется
// и не дублируется. buffer должен быть >= historyCap, иначе старейшая часть
// истории отбрасывается.
func (b *Broadcaster[T]) SubscribeWithReplay(buffer int) <-chan T {
	ch := make(chan T, buffer)

	b.mu.Lock()
	defer b.mu.Unlock()

	select {
	case <-b.ctx.Done():
		close(ch)
	default:
		start := len(b.history) - buffer
		if start < 0 {
			start = 0
		}
		for _, event := range b.history[start:] {
			ch <- event // buffer гарантированно вмещает history[start:]
		}
		b.subs[ch] = struct{}{}
	}

	return ch
}

func (b *Broadcaster[T]) Unsubscribe(ch <-chan T) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for sub := range b.subs {
		if sub == ch {
			delete(b.subs, sub)
			close(sub)
			return
		}
	}
}

func (b *Broadcaster[T]) Publish(event T) {
	if b.historyCap > 0 {
		// Полный лок: append в history должен быть атомарен с доставкой,
		// иначе SubscribeWithReplay может продублировать/потерять событие.
		b.mu.Lock()
		defer b.mu.Unlock()
		if len(b.history) == b.historyCap {
			copy(b.history, b.history[1:])
			b.history[len(b.history)-1] = event
		} else {
			b.history = append(b.history, event)
		}
		b.deliverLocked(event)
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	b.deliverLocked(event)
}

func (b *Broadcaster[T]) deliverLocked(event T) {
	for ch := range b.subs {
		select {
		case ch <- event:
		case <-b.ctx.Done():
			return
		default:
			// slow subscriber → drop event
		}
	}
}

func (b *Broadcaster[T]) Close() {
	b.once.Do(func() {
		b.cancel()
	})
}

func (b *Broadcaster[T]) closeAll() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for ch := range b.subs {
		close(ch)
	}
	b.subs = nil
}
