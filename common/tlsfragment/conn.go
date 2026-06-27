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

// oobChar is the placeholder byte sent as out-of-band (urgent, MSG_OOB) data at
// a split boundary for the oob/disoob desync; the real boundary byte follows in
// the next segment. byedpi's default OOB byte is 'a'.
const oobChar byte = 'a'

// Split-position anchors (byedpi gen_offset model). When splitAnchor is empty
// the ClientHello is split at a random byte inside each SNI label (the original
// behaviour). Otherwise a single split point is computed as the anchor plus a
// signed splitPosition offset:
//
//	sni      → SNI start  + offset   (byedpi `+s`,  e.g. `-s1+s`)
//	sni_end  → SNI end    + offset   (byedpi `+se`, e.g. `-r-5+se`)
//	sni_mid  → SNI middle + offset   (byedpi `+sm`)
//	absolute → offset from start, or from end when negative
const (
	splitAnchorSNI      = "sni"
	splitAnchorSNIEnd   = "sni_end"
	splitAnchorSNIMid   = "sni_mid"
	splitAnchorAbsolute = "absolute"
)

type Conn struct {
	net.Conn
	tcpConn            *net.TCPConn
	ctx                context.Context
	firstPacketWritten bool
	splitPacket        bool
	splitRecord        bool
	disorder           bool
	oob                bool
	disoob             bool
	splitPosition      int
	splitAnchor        string
	fallbackDelay      time.Duration
}

func NewConn(conn net.Conn, ctx context.Context, splitPacket bool, splitRecord bool, disorder bool, oob bool, disoob bool, splitPosition int, splitAnchor string, fallbackDelay time.Duration) *Conn {
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
		oob:           oob,
		disoob:        disoob,
		splitPosition: splitPosition,
		splitAnchor:   splitAnchor,
		fallbackDelay: fallbackDelay,
	}
}

// computeSplitPos resolves the configured byedpi-style split position to an
// absolute byte index in the ClientHello, or -1 when splitAnchor is unset/unknown.
func (c *Conn) computeSplitPos(sn *MyServerName, total int) int {
	switch c.splitAnchor {
	case splitAnchorSNI:
		return sn.Index + c.splitPosition
	case splitAnchorSNIEnd:
		return sn.Index + sn.Length + c.splitPosition
	case splitAnchorSNIMid:
		return sn.Index + sn.Length/2 + c.splitPosition
	case splitAnchorAbsolute:
		if c.splitPosition < 0 {
			return total + c.splitPosition
		}
		return c.splitPosition
	}
	return -1
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.firstPacketWritten {
		defer func() {
			c.firstPacketWritten = true
		}()
		serverName := IndexTLSServerName(b)
		if serverName != nil {
			// "segmented" = we send the ClientHello as multiple TCP segments.
			// splitPacket/disorder/oob/disoob all need this; disorder/disoob
			// additionally send the first segment at TTL=1, and oob/disoob send
			// each non-final segment with a trailing out-of-band (urgent) byte.
			segmented := c.splitPacket || c.disorder || c.oob || c.disoob
			if segmented {
				if c.tcpConn != nil {
					err = c.tcpConn.SetNoDelay(true)
					if err != nil {
						return
					}
				}
			}
			var splitIndexes []int
			if c.splitAnchor != "" {
				// Explicit byedpi-style split position relative to the SNI: one
				// split point at the computed offset. Out-of-range positions
				// fall through to the unmodified-send guard below.
				pos := c.computeSplitPos(serverName, len(b))
				if pos > recordLayerHeaderLen && pos < len(b) {
					splitIndexes = []int{pos}
				}
			} else {
				// Default: split at a random byte inside each label of the
				// registrable SNI (the original tlsfragment behaviour).
				splits := strings.Split(serverName.ServerName, ".")
				currentIndex := serverName.Index
				if publicSuffix := publicsuffix.List.PublicSuffix(serverName.ServerName); publicSuffix != "" {
					splits = splits[:len(splits)-strings.Count(serverName.ServerName, ".")]
				}
				if len(splits) > 1 && splits[0] == "..." {
					currentIndex += len(splits[0]) + 1
					splits = splits[1:]
				}
				for i, split := range splits {
					// Guard rand.Intn(0): an empty label (trailing dot,
					// bare/blank SNI) would panic. The accelerator runs against
					// arbitrary user-supplied SNI, so pin to the label start.
					splitAt := 0
					if len(split) > 0 {
						splitAt = rand.Intn(len(split))
					}
					splitIndexes = append(splitIndexes, currentIndex+splitAt)
					currentIndex += len(split)
					if i != len(splits)-1 {
						currentIndex++
					}
				}
			}
			if len(splitIndexes) == 0 {
				// No label to split around — send the ClientHello unmodified
				// rather than indexing an empty slice below.
				if c.tcpConn != nil {
					_ = c.tcpConn.SetNoDelay(false)
				}
				return c.Conn.Write(b)
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
					case (c.disorder || c.disoob) && i == 0 && c.tcpConn != nil:
						// disorder/disoob: first segment egresses at TTL=1 — it
						// dies one hop out (DPI sees it, the server never does),
						// then the kernel retransmits the same bytes at the
						// restored TTL, so the server reassembles a stream the DPI
						// saw out of order. disoob additionally sends that first
						// segment with a trailing out-of-band (urgent) byte.
						// NODELAY (set above) hands it to the stack at once; the
						// sleep lets it leave before TTL is restored.
						// NOTE: reusing writeAndWaitAck here would HANG on linux —
						// that gate waits for an ACK (TCP_INFO.Unacked==0) which
						// never comes for a TTL=1 segment. darwin sendto is async
						// (Apple DTS 726398); a precise SO_NWRITE flush-gate is a
						// planned hardening over this sleep.
						origV4, origV6, _ := lowerTTL(c.tcpConn, 1)
						if c.disoob {
							_, err = sendOOB(c.tcpConn, payload, oobChar)
						} else {
							_, err = c.Conn.Write(payload)
						}
						if err == nil {
							time.Sleep(c.fallbackDelay)
						}
						_ = restoreTTL(c.tcpConn, origV4, origV6)
						if err != nil {
							return
						}
					case (c.oob || c.disoob) && i != len(splitIndexes) && c.tcpConn != nil:
						// oob/disoob: send this segment followed by a fake urgent
						// (MSG_OOB) byte standing in for the boundary byte, which
						// is re-sent at the head of the next segment. A DPI that
						// folds urgent data inline mis-parses the SNI; the server
						// (urgent byte delivered out-of-band) reassembles the real
						// ClientHello. On platforms without an OOB path this
						// degrades to a plain segment write (oob_other.go).
						_, err = sendOOB(c.tcpConn, payload, oobChar)
						if err != nil {
							return
						}
						time.Sleep(c.fallbackDelay)
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
