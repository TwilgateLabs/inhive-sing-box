package tf

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/publicsuffix"
)

type Conn struct {
	net.Conn
	tcpConn            *net.TCPConn
	ctx                context.Context
	firstPacketWritten bool
	splitPacket        bool
	splitRecord        bool
	disorder           bool
	fallbackDelay      time.Duration
}

func NewConn(conn net.Conn, ctx context.Context, splitPacket bool, splitRecord bool, disorder bool, fallbackDelay time.Duration) *Conn {
	if fallbackDelay == 0 {
		fallbackDelay = C.TLSFragmentFallbackDelay
	}
	tcpConn, _ := N.UnwrapReader(conn).(*net.TCPConn)
	return &Conn{
		Conn:          conn,
		tcpConn:       tcpConn,
		ctx:           ctx,
		splitPacket:   splitPacket,
		splitRecord:   splitRecord,
		disorder:      disorder,
		fallbackDelay: fallbackDelay,
	}
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.firstPacketWritten {
		defer func() {
			c.firstPacketWritten = true
		}()
		serverName := IndexTLSServerName(b)
		if serverName != nil {
			// "segmented" = we send the ClientHello as multiple TCP segments.
			// Both splitPacket and disorder need this; disorder additionally
			// sends the first segment at TTL=1.
			segmented := c.splitPacket || c.disorder
			if segmented {
				if c.tcpConn != nil {
					err = c.tcpConn.SetNoDelay(true)
					if err != nil {
						return
					}
				}
			}
			splits := strings.Split(serverName.ServerName, ".")
			currentIndex := serverName.Index
			if publicSuffix := publicsuffix.List.PublicSuffix(serverName.ServerName); publicSuffix != "" {
				splits = splits[:len(splits)-strings.Count(serverName.ServerName, ".")]
			}
			if len(splits) > 1 && splits[0] == "..." {
				currentIndex += len(splits[0]) + 1
				splits = splits[1:]
			}
			var splitIndexes []int
			for i, split := range splits {
				splitAt := rand.Intn(len(split))
				splitIndexes = append(splitIndexes, currentIndex+splitAt)
				currentIndex += len(split)
				if i != len(splits)-1 {
					currentIndex++
				}
			}
			var buffer bytes.Buffer
			for i := 0; i <= len(splitIndexes); i++ {
				var payload []byte
				if i == 0 {
					payload = b[:splitIndexes[i]]
					if c.splitRecord {
						payload = payload[recordLayerHeaderLen:]
					}
				} else if i == len(splitIndexes) {
					payload = b[splitIndexes[i-1]:]
				} else {
					payload = b[splitIndexes[i-1]:splitIndexes[i]]
				}
				if c.splitRecord {
					if segmented {
						buffer.Reset()
					}
					payloadLen := uint16(len(payload))
					buffer.Write(b[:3])
					binary.Write(&buffer, binary.BigEndian, payloadLen)
					buffer.Write(payload)
					if segmented {
						payload = buffer.Bytes()
					}
				}
				if segmented {
					switch {
					case c.disorder && i == 0 && c.tcpConn != nil:
						// disorder: first segment egresses at TTL=1 — it dies one
						// hop out (DPI sees it, the server never does), then the
						// kernel retransmits the same bytes at the restored TTL,
						// so the server reassembles a stream the DPI saw out of
						// order. NODELAY (set above) hands it to the stack at once;
						// the sleep lets it leave before TTL is restored.
						// NOTE: reusing writeAndWaitAck here would HANG on linux —
						// that gate waits for an ACK (TCP_INFO.Unacked==0) which
						// never comes for a TTL=1 segment. darwin sendto is async
						// (Apple DTS 726398); a precise SO_NWRITE flush-gate is a
						// planned hardening over this sleep.
						origV4, origV6, _ := lowerTTL(c.tcpConn, 1)
						_, err = c.Conn.Write(payload)
						if err == nil {
							time.Sleep(c.fallbackDelay)
						}
						_ = restoreTTL(c.tcpConn, origV4, origV6)
						if err != nil {
							return
						}
					case c.tcpConn != nil && i != len(splitIndexes):
						err = writeAndWaitAck(c.ctx, c.tcpConn, payload, c.fallbackDelay)
						if err != nil {
							return
						}
					default:
						_, err = c.Conn.Write(payload)
						if err != nil {
							return
						}
						if i != len(splitIndexes) {
							time.Sleep(c.fallbackDelay)
						}
					}
				}
			}
			if c.splitRecord && !segmented {
				_, err = c.Conn.Write(buffer.Bytes())
				if err != nil {
					return
				}
			}
			if c.tcpConn != nil {
				err = c.tcpConn.SetNoDelay(false)
				if err != nil {
					return
				}
			}
			return len(b), nil
		}
	}
	return c.Conn.Write(b)
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return c.firstPacketWritten
}

func (c *Conn) Upstream() any {
	return c.Conn
}
