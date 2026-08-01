package xhttp

import (
	"bufio"
	"encoding/binary"
	"io"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Stream-down framing (Xray "Variant 2", XTLS/Xray-core PR #6562).
//
// InHive 2026-08-01: порт клиентской (и симметричной серверной) половины из
// нашего же PR B в Xray. Формат ЗАМОРОЖЕН и обязан совпадать с ним байт-в-байт —
// наш клиент должен понимать И наш патченый Xray-сервер, И (после мёржа) апстрим.
// Пиновка провода: framer_test.go / TestFramerWireFormatMatchesXray.
//
// Зачем: в packet-up (и stream-up) download-половина сессии — один долгоживущий
// GET. При bulk-аплоаде он законно молчит, а фронтящий CDN режет молчащий
// response по idle-таймауту (nginx proxy_read_timeout 60с, CF edge ~100с) →
// сессия виснет насмерть. Фрейминг даёт серверу возможность вкраплять
// keepalive-записи в тишину, не трогая туннелируемые байты.
//
// Когда обе стороны договорились (маркер запроса + подтверждающий заголовок
// ответа, см. dialer.go/server.go), тело stream-down — последовательность
// length-prefixed записей вместо сырого потока:
//
//	record := uvarint(hdr) || payload
//	hdr    := (len << 1) | kind      // kind: 0 = data, 1 = padding(keepalive)
//
// data-запись несёт `len` байт туннелируемого payload'а. padding-запись несёт
// `len` байт СЛУЧАЙНОГО мусора, который читатель выбрасывает; она существует
// только чтобы создать трафик на проводе. Случайный (а не нулевой) паддинг не
// оставляет периодического 0x00-маркера в plaintext, за который мог бы
// зацепиться терминирующий TLS эдж.
const (
	frameKindData    = 0
	frameKindPadding = 1

	// maxFrameRecord ограничивает payload одной записи. При рассинхроне
	// (старый/новый пир, middlebox покорёжил тело) падаем ГРОМКО здесь, а не
	// тихо корраптим туннель.
	maxFrameRecord = 2 * 1024 * 1024 // 2 MiB

	// downFrameConfirmHeader — заголовок ответа, которым сервер подтверждает,
	// что тело stream-down отфреймлено. Клиент включает стриппер ТОЛЬКО увидев
	// его, поэтому старый (нефреймящий) сервер читается как сырой поток.
	downFrameConfirmHeader = "X-Down-Frame"
)

// appendRecord дописывает одну запись (заголовок + payload) в dst. Единственный
// энкодер для обоих путей (data и padding) — у формата ровно один источник
// истины.
func appendRecord(dst []byte, kind uint64, payload []byte) []byte {
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], (uint64(len(payload))<<1)|kind)
	dst = append(dst, hdr[:n]...)
	dst = append(dst, payload...)
	return dst
}

var framerBufPool = sync.Pool{
	New: func() any { return new([]byte) },
}

// downFramer оборачивает серверный stream-down writer (httpServerConn) и
// превращает каждый Write в одну data-запись. Плюс WritePadding для
// keepalive-горутины. Общий мьютекс гарантирует, что keepalive не влезет внутрь
// data-записи, а каждая запись уходит в нижний writer ОДНИМ Write.
//
// Инвариант «один Write» принципиален: httpServerConn.Write делает Flush на
// КАЖДЫЙ вызов, поэтому раздельная запись заголовка и payload'а (а) пустила бы
// keepalive-горутину между ними и (б) разрезала бы одну запись на два
// HTTP/1.1-чанка.
type downFramer struct {
	mu        sync.Mutex
	w         io.Writer
	lastWrite time.Time
}

func newDownFramer(w io.Writer) *downFramer {
	return &downFramer{w: w, lastWrite: time.Now()}
}

func (f *downFramer) writeRecord(kind uint64, payload []byte) error {
	bufPtr := framerBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	buf = appendRecord(buf, kind, payload)
	_, err := f.w.Write(buf)
	*bufPtr = buf
	framerBufPool.Put(bufPtr)
	return err
}

// Write фреймит b в одну или несколько data-записей. Payload больше
// maxFrameRecord режется, чтобы guard читателя оставался осмысленным.
func (f *downFramer) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	total := 0
	for {
		chunk := b
		if len(chunk) > maxFrameRecord {
			chunk = chunk[:maxFrameRecord]
		}
		if err := f.writeRecord(frameKindData, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		f.lastWrite = time.Now()
		b = b[len(chunk):]
		if len(b) == 0 {
			break
		}
	}
	return total, nil
}

// WritePadding пишет keepalive-запись, только если соединение молчало (не было
// data-записи) минимум idle. Возвращает, была ли запись, и ошибку записи —
// чтобы таймер вызывающего отступал, пока идут реальные данные.
func (f *downFramer) WritePadding(idle time.Duration, payload []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if time.Since(f.lastWrite) < idle {
		return false, nil
	}
	if len(payload) > maxFrameRecord {
		payload = payload[:maxFrameRecord]
	}
	if err := f.writeRecord(frameKindPadding, payload); err != nil {
		return false, err
	}
	return true, nil
}

// Close пробрасывает закрытие в нижний writer, если тот закрываем.
func (f *downFramer) Close() error {
	if c, ok := f.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// framedReader снимает stream-down фрейминг на клиенте: разбирает записи из
// нижнего reader'а, выбрасывает padding и отдаёт data-payload'ы. Одна запись
// может отдаваться за сколько угодно Read-вызовов; остаток хранится между ними.
type framedReader struct {
	br        *bufio.Reader
	closer    io.Closer
	remaining int // непрочитанные байты текущей data-записи
}

func newFramedReader(rc io.ReadCloser) *framedReader {
	return &framedReader{
		br:     bufio.NewReader(rc),
		closer: rc,
	}
}

func (r *framedReader) Read(p []byte) (int, error) {
	// Доходим до следующей data-записи с непрочитанным payload'ом, пропуская
	// padding и пустые data-записи.
	for r.remaining == 0 {
		hdr, err := binary.ReadUvarint(r.br)
		if err != nil {
			return 0, err
		}
		length := int(hdr >> 1)
		kind := hdr & 1
		if length < 0 || length > maxFrameRecord {
			return 0, E.New("xhttp: stream-down record too large: ", length)
		}
		if kind == frameKindPadding {
			if _, err := io.CopyN(io.Discard, r.br, int64(length)); err != nil {
				// Короткое чтение внутри записи — рассинхрон, а не чистый конец.
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return 0, err
			}
			continue
		}
		r.remaining = length
	}

	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	read, err := r.br.Read(p[:n])
	r.remaining -= read
	// Нижний поток кончился посреди payload'а data-записи.
	if err == io.EOF && r.remaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	return read, err
}

func (r *framedReader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}
