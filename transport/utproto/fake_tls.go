package utproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// fakeTLSConn wraps a net.Conn so that every Write is emitted as a TLS
// application-data record (\x17\x03\x03 <len:uint16> <payload>) and every
// Read unframes one or more such records and returns the inner bytes.
//
// This is the minimal FakeTLS framing required after the ClientHello /
// ServerHello handshake completes. The server side of mtprotoproxy.py
// uses exactly this framing (see class FakeTLSStreamReader/Writer).
type fakeTLSConn struct {
	net.Conn
	readBuf bytes.Buffer
}

const (
	tlsAppData       byte = 0x17
	tlsMaxRecordSize int  = 16384
)

var tlsRecordHeader = [3]byte{tlsAppData, 0x03, 0x03}

func newFakeTLSConn(c net.Conn) *fakeTLSConn {
	return &fakeTLSConn{Conn: c}
}

func (f *fakeTLSConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > tlsMaxRecordSize {
			chunkSize = tlsMaxRecordSize
		}
		frame := make([]byte, 5+chunkSize)
		frame[0] = tlsRecordHeader[0]
		frame[1] = tlsRecordHeader[1]
		frame[2] = tlsRecordHeader[2]
		binary.BigEndian.PutUint16(frame[3:5], uint16(chunkSize))
		copy(frame[5:], p[:chunkSize])
		if _, err := f.Conn.Write(frame); err != nil {
			return total, err
		}
		total += chunkSize
		p = p[chunkSize:]
	}
	return total, nil
}

func (f *fakeTLSConn) Read(p []byte) (int, error) {
	if f.readBuf.Len() == 0 {
		if err := f.readOneRecord(); err != nil {
			return 0, err
		}
	}
	return f.readBuf.Read(p)
}

func (f *fakeTLSConn) readOneRecord() error {
	var hdr [5]byte
	if _, err := io.ReadFull(f.Conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != tlsRecordHeader[0] || hdr[1] != tlsRecordHeader[1] || hdr[2] != tlsRecordHeader[2] {
		return errors.New("utproto: bad TLS record header")
	}
	length := int(binary.BigEndian.Uint16(hdr[3:5]))
	if length == 0 || length > tlsMaxRecordSize {
		return errors.New("utproto: bad TLS record length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(f.Conn, body); err != nil {
		return err
	}
	f.readBuf.Write(body)
	return nil
}
