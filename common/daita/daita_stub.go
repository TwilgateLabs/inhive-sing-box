//go:build !daita

// Stub implementation when DAITA is not compiled in.
package daita

import "net"

// Framework is a no-op stub.
type Framework struct{}

func NewFramework(machinesStr string, maxPaddingFrac, maxBlockingFrac float64) (*Framework, error) {
	return nil, nil
}

func (f *Framework) Close() {}

// Wrap returns conn unchanged when DAITA is not compiled.
func Wrap(conn net.Conn, fw *Framework) net.Conn {
	return conn
}
