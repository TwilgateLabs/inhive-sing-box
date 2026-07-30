//go:build go1.24

package tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"golang.org/x/crypto/cryptobyte"
)

func parseECHClientConfig(ctx context.Context, logger logger.ContextLogger, serverName string, clientConfig ECHCapableConfig, options option.OutboundTLSOptions) (Config, error) {
	var echConfig []byte
	if len(options.ECH.Config) > 0 {
		echConfig = []byte(strings.Join(options.ECH.Config, "\n"))
	} else if options.ECH.ConfigPath != "" {
		content, err := os.ReadFile(options.ECH.ConfigPath)
		if err != nil {
			return nil, E.Cause(err, "read ECH config")
		}
		echConfig = content
	}
	//nolint:staticcheck
	if options.ECH.PQSignatureSchemesEnabled || options.ECH.DynamicRecordSizingDisabled {
		return nil, E.New("legacy ECH options are deprecated in sing-box 1.12.0 and removed in sing-box 1.13.0")
	}
	if len(echConfig) > 0 {
		block, rest := pem.Decode(echConfig)
		if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
			return nil, E.New("invalid ECH configs pem")
		}
		clientConfig.SetECHConfigList(block.Bytes)
		return clientConfig, nil
	} else {
		return &ECHClientConfig{
			ECHCapableConfig: clientConfig,
			dnsRouter:        service.FromContext[adapter.DNSRouter](ctx),
			queryServerName:  options.ECH.QueryServerName,
			logger:           logger,
			serverName:       serverName,
		}, nil
	}
}

func parseECHServerConfig(ctx context.Context, options option.InboundTLSOptions, tlsConfig *tls.Config, echKeyPath *string) error {
	var echKey []byte
	if len(options.ECH.Key) > 0 {
		echKey = []byte(strings.Join(options.ECH.Key, "\n"))
	} else if options.ECH.KeyPath != "" {
		content, err := os.ReadFile(options.ECH.KeyPath)
		if err != nil {
			return E.Cause(err, "read ECH keys")
		}
		echKey = content
		*echKeyPath = options.ECH.KeyPath
	} else {
		return E.New("missing ECH keys")
	}
	echKeys, err := parseECHKeys(echKey)
	if err != nil {
		return E.Cause(err, "parse ECH keys")
	}
	tlsConfig.EncryptedClientHelloKeys = echKeys
	//nolint:staticcheck
	if options.ECH.PQSignatureSchemesEnabled || options.ECH.DynamicRecordSizingDisabled {
		return E.New("legacy ECH options are deprecated in sing-box 1.12.0 and removed in sing-box 1.13.0")
	}
	return nil
}

func (c *STDServerConfig) setECHServerConfig(echKey []byte) error {
	echKeys, err := parseECHKeys(echKey)
	if err != nil {
		return err
	}
	c.access.Lock()
	config := c.config.Clone()
	config.EncryptedClientHelloKeys = echKeys
	c.config = config
	c.access.Unlock()
	return nil
}

func parseECHKeys(echKey []byte) ([]tls.EncryptedClientHelloKey, error) {
	block, _ := pem.Decode(echKey)
	if block == nil || block.Type != "ECH KEYS" {
		return nil, E.New("invalid ECH keys pem")
	}
	echKeys, err := UnmarshalECHKeys(block.Bytes)
	if err != nil {
		return nil, E.Cause(err, "parse ECH keys")
	}
	return echKeys, nil
}

type ECHClientConfig struct {
	ECHCapableConfig
	access          sync.Mutex
	dnsRouter       adapter.DNSRouter
	queryServerName string
	lastTTL         time.Duration
	lastUpdate      time.Time

	// InHive: only for the honest warning in STDConfig (see there).
	logger       logger.ContextLogger
	serverName   string
	warnQUICOnce sync.Once
}

// STDConfig — InHive: honest warning about ECH silently not applying.
//
// This type exists ONLY for the DNS-fetched ECH flow: parseECHClientConfig
// returns it when the config carries no inline ECHConfigList, and the list is
// fetched from an HTTPS-RR inside ClientHandshake. An inline list never reaches
// here — that path returns the plain client config with the list already set.
//
// Anything that consumes TLS through STDConfig() never calls our ClientHandshake
// and therefore never triggers that fetch: it takes the *tls.Config and runs the
// handshake itself. In this build that means every QUIC consumer — hysteria2 and
// tuic (via sing-quic quic.go), plus the DoQ/DoH3 resolvers (dns/transport/quic).
// So on those the fetch never happens, EncryptedClientHelloConfigList stays
// empty, and ECH is silently OFF while the user believes the SNI is hidden.
//
// A silent privacy downgrade is exactly what must not stay silent (Stability
// bar), so we say it once per config and return the underlying std config
// unchanged — degrading loudly, never failing the connection. Gate is
// "STDConfig was called", not a protocol list: it is the precise property that
// causes the miss, so a future QUIC-ish consumer is covered automatically and
// no TCP protocol is ever warned at by accident.
//
// NOT covered here: making it actually work (eager fetch). STDConfig has no
// context and no deadline, and is called on the construction path, so a blocking
// DNS round-trip here would stall engine start on a hostile network. Deliberately
// left to the caller-side design; see the ECH note in CHANGELOG.
func (s *ECHClientConfig) STDConfig() (*STDConfig, error) {
	s.warnQUICOnce.Do(func() {
		if s.logger != nil {
			s.logger.Warn("ECH is enabled for ", s.serverName,
				" but its config list is fetched over DNS (no inline ech= blob), and this",
				" connection type (QUIC: hysteria2/tuic/DoQ/DoH3) cannot perform that fetch",
				" — ECH is NOT active here and the SNI is sent in plaintext. Use a server",
				" that ships an inline ECH config, or a TCP-based protocol, if you need ECH.")
		}
	})
	return s.ECHCapableConfig.STDConfig()
}

func (s *ECHClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	tlsConn, err := s.fetchAndHandshake(ctx, conn)
	if err != nil {
		return nil, err
	}
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (s *ECHClientConfig) fetchAndHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if len(s.ECHConfigList()) == 0 || s.lastTTL == 0 || time.Since(s.lastUpdate) > s.lastTTL {
		queryServerName := s.queryServerName
		if queryServerName == "" {
			queryServerName = s.ServerName()
		}
		message := &mDNS.Msg{
			MsgHdr: mDNS.MsgHdr{
				RecursionDesired: true,
			},
			Question: []mDNS.Question{
				{
					Name:   mDNS.Fqdn(queryServerName),
					Qtype:  mDNS.TypeHTTPS,
					Qclass: mDNS.ClassINET,
				},
			},
		}
		response, err := s.dnsRouter.Exchange(ctx, message, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, E.Cause(err, "fetch ECH config list")
		}
		if response.Rcode != mDNS.RcodeSuccess {
			return nil, E.Cause(dns.RcodeError(response.Rcode), "fetch ECH config list")
		}
	match:
		for _, rr := range response.Answer {
			switch resource := rr.(type) {
			case *mDNS.HTTPS:
				for _, value := range resource.Value {
					if value.Key().String() == "ech" {
						echConfigList, err := base64.StdEncoding.DecodeString(value.String())
						if err != nil {
							return nil, E.Cause(err, "decode ECH config")
						}
						s.lastTTL = time.Duration(rr.Header().Ttl) * time.Second
						s.lastUpdate = time.Now()
						s.SetECHConfigList(echConfigList)
						break match
					}
				}
			}
		}
		if len(s.ECHConfigList()) == 0 {
			return nil, E.New("no ECH config found in DNS records")
		}
	}
	return s.Client(conn)
}

func (s *ECHClientConfig) Clone() Config {
	return &ECHClientConfig{
		ECHCapableConfig: s.ECHCapableConfig.Clone().(ECHCapableConfig),
		dnsRouter:        s.dnsRouter,
		queryServerName:  s.queryServerName,
		lastUpdate:       s.lastUpdate,
	}
}

func UnmarshalECHKeys(raw []byte) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	rawString := cryptobyte.String(raw)
	for !rawString.Empty() {
		var key tls.EncryptedClientHelloKey
		if !rawString.ReadUint16LengthPrefixed((*cryptobyte.String)(&key.PrivateKey)) {
			return nil, E.New("error parsing private key")
		}
		if !rawString.ReadUint16LengthPrefixed((*cryptobyte.String)(&key.Config)) {
			return nil, E.New("error parsing config")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, E.New("empty ECH keys")
	}
	return keys, nil
}
