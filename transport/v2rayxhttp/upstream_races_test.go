package xhttp

// Тесты на две гонки, закрытые апстримом Xray 26.9.9, и на наши свойства,
// которые из этих правок следуют:
//
//	77f98eba «XHTTP client: Fix a race condition and a data race» (#6665)
//	         → DefaultDialerClient.closed: atomic.Bool вместо голого bool.
//	eef6e63b «XHTTP client: Fix a data race in WaitReadCloser» (#6694)
//	         → reader atomic.Pointer + Swap(nil) + done.Instance.
//
// Тесты написаны на СВОЙСТВА, а не на конкретный исход конкретного порядка:
// «тело закрывается ровно один раз при любом порядке Set/Read/Close»,
// «Read после Close детерминированно даёт io.ErrClosedPipe», «флаг closed
// переживает одновременные запись и чтение». На старом коде падают:
// exactly-once и read-after-close — обычным assert'ом (старый Close звал
// Close тела на каждый вызов, старый Read лез в уже закрытое тело), гонка
// флага — под `go test -race`.

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/xray/signal/done"
	"github.com/sagernet/sing-box/option"
)

// countingBody — io.ReadCloser, который считает свои Close'ы и Read'ы.
// Счётчики атомарные: сам helper не должен быть источником сообщений
// детектора гонок, иначе тест перестаёт что-либо проверять.
type countingBody struct {
	closes atomic.Int32
	reads  atomic.Int32
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	if b.closes.Load() > 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > 0 {
		p[0] = 'x'
	}
	return 1, nil
}

func (b *countingBody) Close() error {
	b.closes.Add(1)
	return nil
}

// В проде по одному и тому же телу штатно бьют два Close'а: conn.Close()
// (conn.go) закрывает reader, а горутина ответа OpenStream закрывает wrc сама
// на non-200. До 26.9.9 это означало два Close нижележащего resp.Body.
func TestWaitReadCloserClosesBodyExactlyOnce(t *testing.T) {
	body := &countingBody{}
	waitReadCloser := &WaitReadCloser{wait: done.New()}
	waitReadCloser.Set(body)

	if err := waitReadCloser.Close(); err != nil {
		t.Fatalf("первый Close: %v", err)
	}
	if err := waitReadCloser.Close(); err != nil {
		t.Fatalf("второй Close: %v", err)
	}
	if got := body.closes.Load(); got != 1 {
		t.Fatalf("тело закрыто %d раз(а), ожидалось ровно 1", got)
	}
}

func TestWaitReadCloserReadAfterCloseIsErrClosedPipe(t *testing.T) {
	body := &countingBody{}
	waitReadCloser := &WaitReadCloser{wait: done.New()}
	waitReadCloser.Set(body)
	_ = waitReadCloser.Close()

	if _, err := waitReadCloser.Read(make([]byte, 4)); err != io.ErrClosedPipe {
		t.Fatalf("Read после Close вернул %v, ожидался io.ErrClosedPipe", err)
	}
	if got := body.reads.Load(); got != 0 {
		t.Fatalf("Read после Close полез в закрытое тело (%d чтений)", got)
	}
}

// Ответ приехал, когда conn уже закрыли: тело обязано быть закрыто, а не
// осиротеть вместе со своим h2-стримом.
func TestWaitReadCloserSetAfterCloseClosesBody(t *testing.T) {
	body := &countingBody{}
	waitReadCloser := &WaitReadCloser{wait: done.New()}
	_ = waitReadCloser.Close()

	waitReadCloser.Set(body)

	if got := body.closes.Load(); got != 1 {
		t.Fatalf("тело после Set-поверх-Close закрыто %d раз(а), ожидалось 1", got)
	}
	if _, err := waitReadCloser.Read(make([]byte, 4)); err != io.ErrClosedPipe {
		t.Fatalf("Read вернул %v, ожидался io.ErrClosedPipe", err)
	}
}

// Читатель, вставший в ожидание тела, обязан освободиться по Close — иначе
// закрытие conn'а оставляет висеть горутину чтения.
func TestWaitReadCloserCloseReleasesWaitingRead(t *testing.T) {
	waitReadCloser := &WaitReadCloser{wait: done.New()}
	readResult := make(chan error, 1)
	go func() {
		_, err := waitReadCloser.Read(make([]byte, 4))
		readResult <- err
	}()

	time.Sleep(20 * time.Millisecond) // дать читателю дойти до ожидания
	_ = waitReadCloser.Close()

	select {
	case err := <-readResult:
		if err != io.ErrClosedPipe {
			t.Fatalf("Read вернул %v, ожидался io.ErrClosedPipe", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read не вернулся после Close — читатель завис в ожидании тела")
	}
}

// Свойство, не исход: при ЛЮБОМ порядке Set/Read/Close тело закрывается ровно
// один раз и никто не паникует. Это ровно та тройка горутин, что есть в проде
// (горутина ответа OpenStream, читатель проксируемого conn, его же Close).
func TestWaitReadCloserConcurrentSetReadClose(t *testing.T) {
	for i := 0; i < 200; i++ {
		body := &countingBody{}
		waitReadCloser := &WaitReadCloser{wait: done.New()}

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			waitReadCloser.Set(body)
		}()
		go func() {
			defer wg.Done()
			_, _ = waitReadCloser.Read(make([]byte, 4))
		}()
		go func() {
			defer wg.Done()
			_ = waitReadCloser.Close()
		}()
		wg.Wait()

		// Ещё один Close — так делает conn.Close() после того, как горутина
		// ответа уже закрыла wrc. Ничего добавить он не должен.
		_ = waitReadCloser.Close()
		if got := body.closes.Load(); got != 1 {
			t.Fatalf("итерация %d: тело закрыто %d раз(а), ожидалось ровно 1", i, got)
		}
	}
}

// Прод-путь флага closed: XmuxManager (mux.go getXmuxClientLocked) читает
// IsClosed() из своей горутины, пока пул закрывает клиента из другой.
func TestDialerClientClosedFlagConcurrentCloseAndRead(t *testing.T) {
	client := &DefaultDialerClient{} // client == nil ⇒ Close только ставит флаг
	stop := make(chan struct{})
	polled := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		defer close(polled)
		close(ready)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = client.IsClosed()
		}
	}()

	// Ждём читателя и пишем долго: детектор гонок сообщает только о доступах,
	// которые реально исполнились с перекрытием. На голом bool этот цикл даёт
	// WARNING: DATA RACE (проверено на копии старой формы), 200 итераций без
	// рукопожатия — не давали.
	<-ready
	for i := 0; i < 200000; i++ {
		_ = client.Close()
	}
	close(stop)
	<-polled

	if !client.IsClosed() {
		t.Fatal("Close не выставил флаг closed")
	}
}

// Вторая половина того же прод-пути: флаг пишет ГОРУТИНА ОТВЕТА OpenStream
// (отказ client.Do), а не Close. Читатель тот же — IsClosed() из пула.
func TestOpenStreamFailureSetsClosedUnderConcurrentPoll(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("занять порт: %v", err)
	}
	deadAddr := listener.Addr().String()
	_ = listener.Close() // теперь по этому адресу гарантированный отказ

	options := option.V2RayXHTTPBaseOptions{}
	client := &DefaultDialerClient{
		options:       &options,
		client:        &http.Client{Transport: &http.Transport{}},
		httpVersion:   "1.1",
		uploadRawPool: &sync.Pool{},
	}

	stop := make(chan struct{})
	polled := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		defer close(polled)
		close(ready)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = client.IsClosed()
		}
	}()

	<-ready
	reader, _, _, _ := client.OpenStream(context.Background(), "http://"+deadAddr+"/", nil, false)
	close(stop)
	<-polled
	if reader != nil {
		_ = reader.Close()
	}

	// Store происходит ДО gotConn.Close(), а OpenStream возвращается только
	// после него — значит флаг обязан быть виден без всяких ожиданий.
	if !client.IsClosed() {
		t.Fatal("отказ дозвона не пометил клиента закрытым")
	}
}
