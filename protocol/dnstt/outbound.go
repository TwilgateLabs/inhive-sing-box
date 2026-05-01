// Package dnstt implements a sing-box outbound for DNSTT (DNS tunneling).
// DNSTT tunnels TCP connections through DNS queries, useful in networks
// where only DNS traffic is permitted.
//
// Based on https://www.bamsoftware.com/software/dnstt/
package dnstt

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const idleTimeout = 2 * time.Minute

// dnsNameCapacity returns how many bytes of payload fit in a DNS name
// after reserving space for the tunnel domain suffix.
func dnsNameCapacity(domain dns.Name) int {
	capacity := 255 - 1 // max DNS name minus null terminator
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64 // max label 63 bytes → 64 to encode
	capacity = capacity * 5 / 8   // base32: 5 bytes → 8 chars
	return capacity
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DnsttOutboundOptions](registry, C.TypeDnstt, NewOutbound)
}

// Outbound is the DNSTT outbound. It maintains a persistent smux session
// over the DNS tunnel and opens a new stream per connection.
type Outbound struct {
	outbound.Adapter
	logger  log.ContextLogger
	pubkey  []byte
	domain  dns.Name
	resolver string
	sess    *smux.Session
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DnsttOutboundOptions) (adapter.Outbound, error) {
	if options.Domain == "" {
		return nil, fmt.Errorf("dnstt: domain is required")
	}
	if options.Pubkey == "" {
		return nil, fmt.Errorf("dnstt: pubkey is required")
	}

	// Decode hex pubkey.
	pubkey, err := noise.DecodeKey(options.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("dnstt: invalid pubkey: %w", err)
	}

	// Parse domain.
	domain, err := dns.ParseName(options.Domain)
	if err != nil {
		return nil, fmt.Errorf("dnstt: invalid domain %q: %w", options.Domain, err)
	}

	resolver := options.Resolver
	if resolver == "" {
		resolver = "8.8.8.8:53"
	}

	ob := &Outbound{
		Adapter:  outbound.NewAdapter(C.TypeDnstt, tag, []string{N.NetworkTCP}, nil),
		logger:   logger,
		pubkey:   pubkey,
		domain:   domain,
		resolver: resolver,
	}

	return ob, nil
}

// DialContext opens a new smux stream over the DNSTT tunnel.
func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	o.logger.InfoContext(ctx, "outbound connection to ", destination)

	sess, err := o.getSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("dnstt: get session: %w", err)
	}

	stream, err := sess.OpenStream()
	if err != nil {
		// Session broken — reset and retry once.
		o.sess = nil
		sess2, err2 := o.getSession(ctx)
		if err2 != nil {
			return nil, fmt.Errorf("dnstt: reopen session: %w", err2)
		}
		stream, err = sess2.OpenStream()
		if err != nil {
			return nil, fmt.Errorf("dnstt: open stream: %w", err)
		}
	}

	return stream, nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("dnstt: UDP not supported")
}

func (o *Outbound) Close() error {
	if o.sess != nil {
		return o.sess.Close()
	}
	return nil
}

// getSession returns the current smux session, creating one if needed.
func (o *Outbound) getSession(ctx context.Context) (*smux.Session, error) {
	if o.sess != nil && !o.sess.IsClosed() {
		return o.sess, nil
	}

	sess, err := o.dial(ctx)
	if err != nil {
		return nil, err
	}
	o.sess = sess
	return sess, nil
}

// dial establishes a new DNSTT smux session.
func (o *Outbound) dial(ctx context.Context) (*smux.Session, error) {
	// Resolve DNS resolver address.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	var err error

	resolver := o.resolver
	switch {
	case strings.HasPrefix(resolver, "https://"):
		// DoH — not yet implemented, fallback to UDP.
		o.logger.Warn("dnstt: DoH resolver not yet supported, using 8.8.8.8:53")
		resolver = "8.8.8.8:53"
		fallthrough
	default:
		// UDP DNS.
		if !strings.Contains(resolver, ":") {
			resolver += ":53"
		}
		remoteAddr, err = net.ResolveUDPAddr("udp", resolver)
		if err != nil {
			return nil, fmt.Errorf("resolve DNS resolver %q: %w", resolver, err)
		}
		pconn, err = net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, fmt.Errorf("open UDP socket: %w", err)
		}
	}

	// Wrap in DNS packet conn (encodes data as DNS queries/responses).
	pconn = NewDNSPacketConn(pconn, remoteAddr, o.domain)

	// MTU: how many bytes fit in DNS name after the tunnel domain.
	mtu := dnsNameCapacity(o.domain) - 8 - 1 - numPadding - 1
	if mtu < 40 {
		pconn.Close()
		return nil, fmt.Errorf("domain %s leaves only %d bytes for payload (too small)", o.domain, mtu)
	}

	// KCP reliable stream on top of DNS PacketConn.
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		pconn.Close()
		return nil, fmt.Errorf("open KCP conn: %w", err)
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if !conn.SetMtu(mtu) {
		conn.Close()
		return nil, fmt.Errorf("set KCP MTU %d failed", mtu)
	}

	// Noise NK encryption on top of KCP.
	rw, err := noise.NewClient(conn, o.pubkey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("noise handshake: %w", err)
	}

	// smux multiplexing on top of Noise.
	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	smuxCfg.KeepAliveTimeout = idleTimeout
	smuxCfg.MaxStreamBuffer = 1 << 20 // 1MB
	sess, err := smux.Client(rw, smuxCfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open smux session: %w", err)
	}

	o.logger.Info("dnstt session established (mtu=", mtu, ")")
	return sess, nil
}

