package xhttp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// nopWriteCloser adapts a bytes.Buffer to io.WriteCloser.
type nopWriteCloser struct{ *bytes.Buffer }

func (nopWriteCloser) Close() error { return nil }

func framedReaderFromBytes(b []byte) *framedReader {
	return newFramedReader(io.NopCloser(bytes.NewReader(b)))
}

// TestFramerWireFormatMatchesXray пинует кодировку на проводе против
// вручную посчитанных байт из эталонной реализации в Xray-core
// (https://github.com/XTLS/Xray-core/pull/6562, тот же порт есть в mihomo).
// Если этот тест когда-нибудь придётся ПРАВИТЬ — сломан interop: наш клиент
// перестанет понимать отфреймленное тело от нашего патченого Xray-сервера (и от
// апстрима после мёржа), и наоборот.
func TestFramerWireFormatMatchesXray(t *testing.T) {
	var wire bytes.Buffer
	framer := newDownFramer(nopWriteCloser{&wire})

	// data "hi" -> hdr = (2<<1)|0 = 4 -> uvarint 0x04, затем "hi"
	if _, err := framer.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	// padding "ab" -> hdr = (2<<1)|1 = 5 -> uvarint 0x05, затем "ab"
	if ok, err := framer.WritePadding(0, []byte("ab")); err != nil || !ok {
		t.Fatalf("WritePadding ok=%v err=%v", ok, err)
	}
	// data из 100 байт -> hdr = (100<<1)|0 = 200 -> uvarint 0xC8 0x01
	big := bytes.Repeat([]byte{'z'}, 100)
	if _, err := framer.Write(big); err != nil {
		t.Fatal(err)
	}

	want := []byte{0x04, 'h', 'i', 0x05, 'a', 'b', 0xC8, 0x01}
	want = append(want, big...)
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("wire format drifted from Xray-core:\n got %x\nwant %x", wire.Bytes(), want)
	}

	// И читатель обязан отдать ровно data-payload'ы.
	got, err := io.ReadAll(framedReaderFromBytes(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, append([]byte("hi"), big...)) {
		t.Fatalf("decoded stream mismatch: %d bytes", len(got))
	}
}

// TestFramedReaderDecodesForeignEncoder декодирует поток, собранный НЕЗАВИСИМЫМ
// энкодером (не нашим downFramer), но по документированному формату. Это
// заменитель «этот ответ отфреймил Xray-сервер»: если читатель понимает только
// байты собственного писателя, формат на самом деле не общий.
func TestFramedReaderDecodesForeignEncoder(t *testing.T) {
	encode := func(kind uint64, payload []byte) []byte {
		var hdr [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(hdr[:], (uint64(len(payload))<<1)|kind)
		return append(append([]byte{}, hdr[:n]...), payload...)
	}

	var wire bytes.Buffer
	wire.Write(encode(1, bytes.Repeat([]byte{0x00}, 300))) // keepalive, 2-байтный заголовок
	wire.Write(encode(0, []byte("first")))
	wire.Write(encode(1, nil)) // keepalive нулевой длины
	wire.Write(encode(0, bytes.Repeat([]byte{'q'}, 70000)))
	wire.Write(encode(0, []byte("last")))

	got, err := io.ReadAll(framedReaderFromBytes(wire.Bytes()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := append([]byte("first"), bytes.Repeat([]byte{'q'}, 70000)...)
	want = append(want, []byte("last")...)
	if !bytes.Equal(got, want) {
		t.Fatalf("foreign-encoded stream mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

// TestFramerRoundTrip: конкатенация записанного через серверный фреймер должна
// побайтово совпасть с прочитанным через клиентский стриппер, и ни один байт
// фрейминга не должен протечь в поток.
func TestFramerRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	framer := newDownFramer(nopWriteCloser{&wire})

	payloads := [][]byte{
		[]byte("hello"),
		{}, // пустая data-запись должна переживаться
		bytes.Repeat([]byte{0xAB}, 5000),
		[]byte("tail"),
	}
	var want bytes.Buffer
	for _, payload := range payloads {
		if _, err := framer.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
		want.Write(payload)
	}

	got, err := io.ReadAll(framedReaderFromBytes(wire.Bytes()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), want.Len())
	}
}

// TestFramerSkipsPadding: keepalive-записи прозрачны для читателя.
func TestFramerSkipsPadding(t *testing.T) {
	var wire bytes.Buffer
	framer := newDownFramer(nopWriteCloser{&wire})

	if _, err := framer.Write([]byte("AAA")); err != nil {
		t.Fatal(err)
	}
	// idle=0 форсит padding независимо от времени простоя.
	if ok, err := framer.WritePadding(0, bytes.Repeat([]byte{'X'}, 128)); err != nil || !ok {
		t.Fatalf("WritePadding ok=%v err=%v", ok, err)
	}
	if _, err := framer.Write([]byte("BBB")); err != nil {
		t.Fatal(err)
	}
	if ok, err := framer.WritePadding(0, nil); err != nil || !ok {
		t.Fatalf("empty WritePadding ok=%v err=%v", ok, err)
	}
	if _, err := framer.Write([]byte("CCC")); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(framedReaderFromBytes(wire.Bytes()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "AAABBBCCC" {
		t.Fatalf("padding leaked into stream: %q", got)
	}
}

// TestFramerPaddingRespectsIdle: пока текут данные, keepalive — no-op.
func TestFramerPaddingRespectsIdle(t *testing.T) {
	var wire bytes.Buffer
	framer := newDownFramer(nopWriteCloser{&wire})
	if _, err := framer.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if ok, _ := framer.WritePadding(time.Hour, []byte("X")); ok {
		t.Fatal("padding written while within idle window")
	}
	if ok, err := framer.WritePadding(0, []byte("X")); err != nil || !ok {
		t.Fatalf("padding not written after idle elapsed: ok=%v err=%v", ok, err)
	}
}

// TestFramerPartialReads: одна большая data-запись отдаётся корректно за много
// мелких Read'ов, остаток переносится между вызовами.
func TestFramerPartialReads(t *testing.T) {
	payload := make([]byte, 40000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	framer := newDownFramer(nopWriteCloser{&wire})
	if _, err := framer.Write(payload); err != nil {
		t.Fatal(err)
	}

	reader := framedReaderFromBytes(wire.Bytes())
	var got bytes.Buffer
	small := make([]byte, 7)
	for {
		n, err := reader.Read(small)
		got.Write(small[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("partial read mismatch: got %d want %d", got.Len(), len(payload))
	}
}

// TestFramerLargePayloadSplit: payload больше maxFrameRecord режется на записи в
// пределах guard'а и собирается обратно байт-в-байт.
func TestFramerLargePayloadSplit(t *testing.T) {
	payload := make([]byte, maxFrameRecord+1234)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	framer := newDownFramer(nopWriteCloser{&wire})
	if _, err := framer.Write(payload); err != nil {
		t.Fatal(err)
	}

	firstHdr, err := binary.ReadUvarint(bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if int(firstHdr>>1) > maxFrameRecord {
		t.Fatalf("first record %d exceeds guard %d", firstHdr>>1, maxFrameRecord)
	}

	got, err := io.ReadAll(framedReaderFromBytes(wire.Bytes()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("large payload mismatch: got %d want %d", len(got), len(payload))
	}
}

// TestFramerMaxRecordGuard: покорёженный/раздутый префикс длины падает громко.
func TestFramerMaxRecordGuard(t *testing.T) {
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(maxFrameRecord+1)<<1)

	_, err := io.ReadAll(framedReaderFromBytes(hdr[:n]))
	if err == nil {
		t.Fatal("expected error on oversized record, got nil")
	}
}

// TestFramerTruncatedRecord: обрезанная запись — ошибка, а не «успешный»
// частичный поток.
func TestFramerTruncatedRecord(t *testing.T) {
	var wire bytes.Buffer
	framer := newDownFramer(nopWriteCloser{&wire})
	if _, err := framer.Write(bytes.Repeat([]byte{'Z'}, 1000)); err != nil {
		t.Fatal(err)
	}
	truncated := wire.Bytes()[:wire.Len()-100] // выкидываем 100 байт payload'а

	_, err := io.ReadAll(framedReaderFromBytes(truncated))
	if err == nil {
		t.Fatal("expected error on truncated record, got nil")
	}
}
