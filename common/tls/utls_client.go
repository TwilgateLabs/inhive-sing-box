//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/http2"
)

type UTLSClientConfig struct {
	ctx                   context.Context
	config                *utls.Config
	id                    utls.ClientHelloID
	fragment              bool
	fragmentFallbackDelay time.Duration
	recordFragment        bool
}

func (c *UTLSClientConfig) ServerName() string {
	return c.config.ServerName
}

func (c *UTLSClientConfig) SetServerName(serverName string) {
	c.config.ServerName = serverName
}

func (c *UTLSClientConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *UTLSClientConfig) SetNextProtos(nextProto []string) {
	if len(nextProto) == 1 && nextProto[0] == http2.NextProtoTLS {
		nextProto = append(nextProto, "http/1.1")
	}
	c.config.NextProtos = nextProto
}

func (c *UTLSClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for uTLS")
}

func (c *UTLSClientConfig) Client(conn net.Conn) (Conn, error) {
	if c.recordFragment {
		conn = tf.NewConn(conn, c.ctx, c.fragment, c.recordFragment, c.fragmentFallbackDelay)
	}
	return &utlsALPNWrapper{utlsConnWrapper{utls.UClient(conn, c.config.Clone(), c.id)}, c.config.NextProtos}, nil
}

func (c *UTLSClientConfig) SetSessionIDGenerator(generator func(clientHello []byte, sessionID []byte) error) {
	c.config.SessionIDGenerator = generator
}

func (c *UTLSClientConfig) Clone() Config {
	return &UTLSClientConfig{
		c.ctx, c.config.Clone(), c.id, c.fragment, c.fragmentFallbackDelay, c.recordFragment,
	}
}

func (c *UTLSClientConfig) ECHConfigList() []byte {
	return c.config.EncryptedClientHelloConfigList
}

func (c *UTLSClientConfig) SetECHConfigList(EncryptedClientHelloConfigList []byte) {
	c.config.EncryptedClientHelloConfigList = EncryptedClientHelloConfigList
}

type utlsConnWrapper struct {
	*utls.UConn
}

func (c *utlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *utlsConnWrapper) Upstream() any {
	return c.UConn
}

func (c *utlsConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *utlsConnWrapper) WriterReplaceable() bool {
	return true
}

type utlsALPNWrapper struct {
	utlsConnWrapper
	nextProtocols []string
}

func (c *utlsALPNWrapper) HandshakeContext(ctx context.Context) error {
	if len(c.nextProtocols) > 0 {
		err := c.BuildHandshakeState()
		if err != nil {
			return err
		}
		for _, extension := range c.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = c.nextProtocols
				err = c.BuildHandshakeState()
				if err != nil {
					return err
				}
				break
			}
		}
	}
	return c.UConn.HandshakeContext(ctx)
}

func NewUTLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	var serverName string
	if options.ServerName != "" {
		serverName = options.ServerName
	} else if serverAddress != "" {
		serverName = serverAddress
	}
	if serverName == "" && !options.Insecure {
		return nil, E.New("missing server_name or insecure=true")
	}

	var tlsConfig utls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	tlsConfig.RootCAs = adapter.RootPoolFromContext(ctx)
	if !options.DisableSNI {
		if options.TLSTricks != nil && options.TLSTricks.MixedCaseSNI {
			tlsConfig.ServerName = randomizeCase(serverName)
		} else {
			tlsConfig.ServerName = serverName
		}
	}
	if options.Insecure {
		tlsConfig.InsecureSkipVerify = options.Insecure
	} else if options.DisableSNI {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("disable_sni is unsupported in reality")
		}
		tlsConfig.InsecureServerNameToVerify = serverName
	}
	if len(options.CertificatePublicKeySHA256) > 0 {
		if len(options.Certificate) > 0 || options.CertificatePath != "" {
			return nil, E.New("certificate_public_key_sha256 is conflict with certificate or certificate_path")
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyPublicKeySHA256(options.CertificatePublicKeySHA256, rawCerts, tlsConfig.Time)
		}
	}
	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = options.ALPN
	}
	if options.MinVersion != "" {
		minVersion, err := ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		tlsConfig.MinVersion = minVersion
	}
	if options.MaxVersion != "" {
		maxVersion, err := ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		tlsConfig.MaxVersion = maxVersion
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(options.Certificate) > 0 {
		certificate = []byte(strings.Join(options.Certificate, "\n"))
	} else if options.CertificatePath != "" {
		content, err := os.ReadFile(options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			// string(): E.New/format.ToString паникует «unknown value» на []byte.
			return nil, E.New("failed to parse certificate:\n\n", string(certificate))
		}
		tlsConfig.RootCAs = certPool
	}
	var clientCertificate []byte
	if len(options.ClientCertificate) > 0 {
		clientCertificate = []byte(strings.Join(options.ClientCertificate, "\n"))
	} else if options.ClientCertificatePath != "" {
		content, err := os.ReadFile(options.ClientCertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read client certificate")
		}
		clientCertificate = content
	}
	var clientKey []byte
	if len(options.ClientKey) > 0 {
		clientKey = []byte(strings.Join(options.ClientKey, "\n"))
	} else if options.ClientKeyPath != "" {
		content, err := os.ReadFile(options.ClientKeyPath)
		if err != nil {
			return nil, E.Cause(err, "read client key")
		}
		clientKey = content
	}
	if len(clientCertificate) > 0 && len(clientKey) > 0 {
		keyPair, err := utls.X509KeyPair(clientCertificate, clientKey)
		if err != nil {
			return nil, E.Cause(err, "parse client x509 key pair")
		}
		tlsConfig.Certificates = []utls.Certificate{keyPair}
	} else if len(clientCertificate) > 0 || len(clientKey) > 0 {
		return nil, E.New("client certificate and client key must be provided together")
	}
	id, err := uTLSClientHelloID(options.UTLS.Fingerprint)
	if err != nil {
		return nil, err
	}
	var config Config = &UTLSClientConfig{ctx, &tlsConfig, id, options.Fragment, time.Duration(options.FragmentFallbackDelay), options.RecordFragment}
	if options.ECH != nil && options.ECH.Enabled {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("Reality is conflict with ECH")
		}
		config, err = parseECHClientConfig(ctx, logger, serverName, config.(ECHCapableConfig), options)
		if err != nil {
			return nil, err
		}
	}
	if (options.KernelRx || options.KernelTx) && !common.PtrValueOrDefault(options.Reality).Enabled {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

var (
	randomFingerprint           utls.ClientHelloID
	randomizedFingerprint       utls.ClientHelloID
	randomizedNoALPNFingerprint utls.ClientHelloID
)

func init() {
	modernFingerprints := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
	}
	randomFingerprint = modernFingerprints[rand.Intn(len(modernFingerprints))]

	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomizedFingerprint = utls.HelloRandomized
	randomizedFingerprint.Seed, _ = utls.NewPRNGSeed()
	randomizedFingerprint.Weights = &weights

	randomizedNoALPNFingerprint = utls.HelloRandomizedNoALPN
	randomizedNoALPNFingerprint.Seed, _ = utls.NewPRNGSeed()
	randomizedNoALPNFingerprint.Weights = &weights
}

// xrayFingerprints — версионные имена отпечатков в написании Xray
// (`transport/internet/tls/tls.go`: ModernFingerprints + OtherFingerprints).
//
// InHive 2026-08-03: апстримный sing-box знает только 11 коротких псевдонимов и
// на всём остальном возвращает ОШИБКУ — а ошибка здесь роняет разбор всего
// outbound'а, то есть сервер из чужой подписки просто исчезает. Xray же принимает
// ~40 имён, и провайдеры их пишут: `fp=randomizednoalpn` (у Xray это вообще
// пресет), `fp=hellochrome_133`, `fp=hellofirefox_105`. Отпечаток влияет только
// на маскировку ClientHello и никак — на протокол, так что отвергать из-за него
// живой сервер нечем оправдать. Границу держим по Xray: что принимает он —
// принимаем и мы, что не принимает он — честно роняем (тихой подмены нет).
var xrayFingerprints = map[string]utls.ClientHelloID{
	"hellogolang":           utls.HelloGolang,
	"hellorandomized":       utls.HelloRandomized,
	"hellorandomizedalpn":   utls.HelloRandomizedALPN,
	"hellorandomizednoalpn": utls.HelloRandomizedNoALPN,

	"hellochrome_auto":                 utls.HelloChrome_Auto,
	"hellochrome_58":                   utls.HelloChrome_58,
	"hellochrome_62":                   utls.HelloChrome_62,
	"hellochrome_70":                   utls.HelloChrome_70,
	"hellochrome_72":                   utls.HelloChrome_72,
	"hellochrome_83":                   utls.HelloChrome_83,
	"hellochrome_87":                   utls.HelloChrome_87,
	"hellochrome_96":                   utls.HelloChrome_96,
	"hellochrome_100":                  utls.HelloChrome_100,
	"hellochrome_100_psk":              utls.HelloChrome_100_PSK,
	"hellochrome_102":                  utls.HelloChrome_102,
	"hellochrome_106_shuffle":          utls.HelloChrome_106_Shuffle,
	"hellochrome_112_psk_shuf":         utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_114_padding_psk_shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_115_pq":               utls.HelloChrome_115_PQ,
	"hellochrome_115_pq_psk":           utls.HelloChrome_115_PQ_PSK,
	"hellochrome_120":                  utls.HelloChrome_120,
	"hellochrome_120_pq":               utls.HelloChrome_120_PQ,
	"hellochrome_131":                  utls.HelloChrome_131,
	"hellochrome_133":                  utls.HelloChrome_133,

	"hellofirefox_auto": utls.HelloFirefox_Auto,
	"hellofirefox_55":   utls.HelloFirefox_55,
	"hellofirefox_56":   utls.HelloFirefox_56,
	"hellofirefox_63":   utls.HelloFirefox_63,
	"hellofirefox_65":   utls.HelloFirefox_65,
	"hellofirefox_99":   utls.HelloFirefox_99,
	"hellofirefox_102":  utls.HelloFirefox_102,
	"hellofirefox_105":  utls.HelloFirefox_105,
	"hellofirefox_120":  utls.HelloFirefox_120,
	// Xray-only (его форк uTLS): у нас в metacubex/utls такого билда нет —
	// отдаём ближайший свежий Firefox вместо отказа.
	"hellofirefox_148": utls.HelloFirefox_120,

	"helloedge_auto": utls.HelloEdge_Auto,
	"helloedge_85":   utls.HelloEdge_85,
	"helloedge_106":  utls.HelloEdge_106,

	"hellosafari_auto": utls.HelloSafari_Auto,
	"hellosafari_16_0": utls.HelloSafari_16_0,
	"hellosafari_26_3": utls.HelloSafari_Auto, // Xray-only, см. выше

	"helloios_auto": utls.HelloIOS_Auto,
	"helloios_11_1": utls.HelloIOS_11_1,
	"helloios_12_1": utls.HelloIOS_12_1,
	"helloios_13":   utls.HelloIOS_13,
	"helloios_14":   utls.HelloIOS_14,

	"hello360_auto": utls.Hello360_Auto,
	"hello360_7_5":  utls.Hello360_7_5,
	"hello360_11_0": utls.Hello360_11_0,

	"helloqq_auto": utls.HelloQQ_Auto,
	"helloqq_11_1": utls.HelloQQ_11_1,

	"helloandroid_11_okhttp": utls.HelloAndroid_11_OkHttp,

	// Написания mihomo/Clash.Meta (component/tls/utls.go): без префикса `hello`
	// и без подчёркивания перед версией. Clash-подписки пишут именно так
	// (`client-fingerprint: chrome120`), и для нас это был очередной
	// исчезнувший сервер.
	"chrome120":  utls.HelloChrome_120,
	"firefox120": utls.HelloFirefox_120,
	"safari16":   utls.HelloSafari_16_0,
}

func uTLSClientHelloID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(name) {
	case "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk":
		fallthrough
	case "chrome", "":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "360":
		return utls.Hello360_Auto, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "random":
		return randomFingerprint, nil
	case "randomized":
		return randomizedFingerprint, nil
	case "randomizednoalpn":
		// Пресет Xray. Свой рандомизированный отпечаток, как и `randomized`
		// выше: seed на процесс, TLS 1.3 обязателен (иначе REALITY некуда
		// положить key_share и хендшейк не состоится вовсе).
		return randomizedNoALPNFingerprint, nil
	}
	if id, loaded := xrayFingerprints[strings.ToLower(name)]; loaded {
		return id, nil
	}
	return utls.ClientHelloID{}, E.New("unknown uTLS fingerprint: ", name)
}
