package buf

import (
	"bytes"
	"testing"
)

// Regression test for the Xray v26.9.9 fix in common/buf/writer.go: Buffer.Write
// reports ErrBufferFull on a *partial* write, which BufferedWriter must treat as
// "flush and continue", not as a failure. Before the fix any Write larger than one
// 8 KiB buffer returned ErrBufferFull after copying only the first chunk.
func TestBufferedWriterWriteLargerThanBuffer(t *testing.T) {
	t.Parallel()

	var sink bytes.Buffer
	w := NewBufferedWriter(&SequentialWriter{Writer: &sink})

	payload := make([]byte, Size*3+123)
	for i := range payload {
		payload[i] = byte(i)
	}

	n, err := w.Write(payload)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned n = %d, want %d", n, len(payload))
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if got := sink.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("sink got %d bytes, want %d (equal=%v)", len(got), len(payload), bytes.Equal(got, payload))
	}
}
