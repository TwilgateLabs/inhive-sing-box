//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var _ ConfigCompat = (*RealityClientConfig)(nil)

// Версия клиента, объявляемая REALITY-серверу в SessionId[0:3]. Держится РАВНОЙ
// Xray-эталону из core/upstream.toml (записи `xhttp`/`xray-common`/`xray2sing`,
// сейчас v26.9.9) — сервер сверяет её с minClientVer/maxClientVer, и застывшая
// версия молча отбрасывалась серверами, которые пускают настоящий Xray
// (замер 2026-08-03: 1.8.1 → VERIFIED=false, реальная версия → true, 3/3).
// Двигать ОДНОВРЕМЕННО с бампом эталона. Подробности — в ClientHandshake.
const (
	realityClientVerX = 26
	realityClientVerY = 9
	realityClientVerZ = 9
)

type RealityClientConfig struct {
	ctx       context.Context
	uClient   *UTLSClientConfig
	publicKey []byte
	shortID   [8]byte
}

func NewRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by reality client")
	}

	uClient, err := NewUTLSClient(ctx, logger, serverAddress, options)
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(options.Reality.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "decode public_key")
	}
	if len(publicKey) != 32 {
		return nil, E.New("invalid public_key")
	}
	var shortID [8]byte
	// Пре-чек длины ОБЯЗАН стоять до hex.Decode: у hex.Decode нет проверки
	// границ dst, sid ≥18 hex-символов паникует index-out-of-range прямо в
	// создании аутбаунда (panic минует hinvalid-fallback и кладёт весь профиль);
	// пост-чек decodedLen > 8 для такого входа недостижим.
	if len(options.Reality.ShortID) > hex.EncodedLen(len(shortID)) {
		return nil, E.New("invalid short_id: ", options.Reality.ShortID)
	}
	decodedLen, err := hex.Decode(shortID[:], []byte(options.Reality.ShortID))
	if err != nil {
		return nil, E.Cause(err, "decode short_id")
	}
	if decodedLen > 8 {
		return nil, E.New("invalid short_id")
	}

	var config Config = &RealityClientConfig{ctx, uClient.(*UTLSClientConfig), publicKey, shortID}
	if options.KernelRx || options.KernelTx {
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

func (e *RealityClientConfig) ServerName() string {
	return e.uClient.ServerName()
}

func (e *RealityClientConfig) SetServerName(serverName string) {
	e.uClient.SetServerName(serverName)
}

func (e *RealityClientConfig) NextProtos() []string {
	return e.uClient.NextProtos()
}

func (e *RealityClientConfig) SetNextProtos(nextProto []string) {
	e.uClient.SetNextProtos(nextProto)
}

func (e *RealityClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for reality")
}

func (e *RealityClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, e)
}

func (e *RealityClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	verifier := &realityVerifier{
		serverName: e.uClient.ServerName(),
	}
	uConfig := e.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	uConn, err := newRealityUConn(conn, uConfig, e.uClient.id)
	if err != nil {
		return nil, err
	}
	verifier.UConn = uConn
	// X25519MLKEM768 — ГАРАНТИРОВАТЬ, а не вырезать (InHive 2026-09-18).
	//
	// Апстримный sing-box (и v1.13.21) вырезает MLKEM из SupportedCurves и
	// KeyShare; mihomo делал так же. XTLS/REALITY 8cdf7bf9 (2026-09-08,
	// Xray >= 26.9.8) перевернул правило: сервер ТРЕБУЕТ keyShare X25519MLKEM768
	// перед опциональным X25519, иначе `break` -> fallback на target. Сломаны
	// все sing-box (#4520), karing, Exclave, Shadowrocket; mihomo v1.19.30 и
	// Xray-клиенты (Happ и др.) шлют гибридный share и работают. Старый сервер
	// (родитель e1986a4d31ca) предпочитает X25519 и MLKEM рядом игнорирует —
	// значит гибридный share совместим с обоими поколениями.
	//
	// Первая гипотеза 2026-09-15 «target disk.yandex.ru не умеет MLKEM»
	// ОПРОВЕРГНУТА прямым замером: ни disk.yandex.ru, ни yandex.ru MLKEM не
	// согласуют, а REALITY при успешной аутентификации отвечает сам — target
	// ему для этого не нужен. Реальная причина 3-из-4 — лотерея отпечатка
	// `randomized`, см. newRealityUConn и его гард.
	// (нормализация MLKEM и пересев randomized — внутри newRealityUConn выше)

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

	// InHive 2026-08-03: версия КЛИЕНТА, которую REALITY-сервер читает из
	// SessionId[0:3] и сверяет с `minClientVer`/`maxClientVer`
	// (XTLS/REALITY tls.go: `Value(ClientVer[:]...) >= Value(MinClientVer...)`).
	//
	// Апстрим sing-box шлёт здесь 1.8.1 — застывший номер, не связанный ни с
	// одной живой версией. Xray-клиент шлёт СВОЮ core-версию (26.x), поэтому
	// любой сервер с выставленным `minClientVer` пускает Xray/Happ/v2rayNG и
	// молча роняет нас: auth не проходит → сервер отдаёт настоящий сертификат
	// dest → у нас `reality verification failed` (а на xhttp-пути и вовсе немой
	// таймаут). Замерено на внешней подписке 2026-08-03, чередованием версий
	// в одном сеансе, 3/3 воспроизводимо:
	//     ver=1.8.1   → VERIFIED=false   (сервер отдал реальный серт dest)
	//     ver=26.7.11 → VERIFIED=true
	//
	// Держим ровно версию Xray-эталона из core/upstream.toml (запись `xhttp`,
	// ref = v26.7.11) — двигать её ВМЕСТЕ с бампом эталона, не отдельно.
	hello.SessionId[0] = realityClientVerX
	hello.SessionId[1] = realityClientVerY
	hello.SessionId[2] = realityClientVerZ
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], e.shortID[:])
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId[:16]: %v\n", hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, err
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, E.New("nil KeyShareKeys")
	}
	ecdheKey := keyShareKeys.Ecdhe
	if ecdheKey == nil {
		// InHive 2026-08-03: когда отпечаток предлагает X25519MLKEM768, uTLS
		// кладёт X25519-половину в MlkemEcdhe и оставляет Ecdhe пустым. Без этой
		// ветки такой отпечаток не мог установить REALITY вовсе — падал на
		// «nil ecdheKey», хотя ключ есть.
		//
		// Так делают И Xray (transport/internet/reality/reality.go), И mihomo
		// (component/tls/reality.go) — из троих без этого оставался только
		// апстримный sing-box (проверено на v1.13.16, свежайшем на дату правки).
		// Вырезание MLKEM выше (оно делает Ecdhe непустым на сегодняшних
		// отпечатках) остаётся дефолтом — mihomo держит его по той же причине:
		// «X25519MLKEM768 does not work properly with the old reality server».
		// Эта ветка — страховка на случай, когда вырезать нечего.
		ecdheKey = keyShareKeys.MlkemEcdhe
	}
	if ecdheKey == nil {
		return nil, E.New("nil ecdheKey")
	}
	authKey, err := ecdheKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		return nil, E.New("nil auth_key")
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId: %v\n", hello.SessionId)
		fmt.Printf("REALITY uConn.AuthKey: %v\n", authKey)
	}

	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}

	if debug.Enabled {
		fmt.Printf("REALITY Conn.Verified: %v\n", verifier.verified)
	}

	if !verifier.verified {
		go realityClientFallback(e.ctx, uConn, e.uClient.ServerName(), e.uClient.id)
		return nil, E.New("reality verification failed")
	}

	return &realityClientConnWrapper{uConn}, nil
}

func realityClientFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
	}
	request, _ := http.NewRequest("GET", "https://"+serverName, nil)
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func (e *RealityClientConfig) Clone() Config {
	return &RealityClientConfig{
		e.ctx,
		e.uClient.Clone().(*UTLSClientConfig),
		e.publicKey,
		e.shortID,
	}
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
}

func (c *realityClientConnWrapper) ConnectionState() tls.ConnectionState {
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

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
// We fixed it by calling Close() directly.
func (c *realityClientConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return true
}

// realityReseedAttempts — сколько раз пересеивать randomized-отпечаток, если
// он вдруг дал spec без TLS 1.3 key_share. С ПРОД-весами (utls_client.go:
// TLSVersMax_Set_VersionTLS13 = 1) такого не бывает — это страховка на случай
// чужих весов или смены поведения utls, а не боевой путь.
const realityReseedAttempts = 8

// newRealityUConn строит uTLS-клиент для REALITY и доводит его ClientHello до
// формы, которую понимает REALITY-сервер любого поколения (InHive 2026-09-18).
//
// Отпечатки Randomized/RandomizedNoALPN в metacubex/utls v1.8.7 кладут
// X25519MLKEM768 в supported_groups и в key_shares двумя НЕЗАВИСИМЫМИ бросками
// монетки (u_parrots.go:3058 и :3117), а Xray >= 26.9.8 (REALITY 8cdf7bf9)
// требует MLKEM-share ПЕРВЫМ и отвергает всё остальное. Гард
// TestRealityClientHello_MLKEMFirst с прод-весами: заметная доля seed'ов
// голого randomized не проходит. Seed у нас один на процесс (utls_client.go),
// то есть неудачный старт ядра клал бы ВСЕ REALITY-аутбаунды с randomized до
// перезапуска — отказ, которого юзер не видит и не может отрепортить.
// (Слой «TLS 1.2-only spec» существует только при DefaultWeights; прод-веса
// его исключают — сюда добавлен пересев как страховка, не как фикс.)
//
// ПОЧЕМУ ПРАВИТСЯ SPEC, А НЕ uConn.Extensions ПОСЛЕ BuildHandshakeState (укусило
// 2026-09-18, 0/4 серверов, `tls: error decoding message`): ключи для key_share
// с пустым Data генерирует ApplyPreset, а его повторный BuildHandshakeState не
// зовёт (clientHelloBuildStatus уже BuildByUtls). Вставленный после сборки
// share уходил на провод пустым. Поэтому: UTLSIdToSpec -> нормализовать ->
// HelloCustom + ApplyPreset (генерирует ключи) -> BuildHandshakeState.
// SNI в spec пустой намеренно — ApplyPreset подставляет config.ServerName;
// ALPN ниже по коду подменяется на config.NextProtos как и раньше.
// Для chrome-пресетов с гибридным share нормализация — no-op.
func newRealityUConn(conn net.Conn, uConfig *utls.Config, id utls.ClientHelloID) (*utls.UConn, error) {
	isRandomized := id.Client == utls.HelloRandomized.Client || id.Client == utls.HelloRandomizedNoALPN.Client
	for attempt := 0; ; attempt++ {
		spec, err := utls.UTLSIdToSpec(id)
		if err != nil {
			return nil, E.Cause(err, "REALITY: fingerprint ", id.Str())
		}
		if specHasKeyShare(&spec) {
			ensureMLKEMFirst(spec.Extensions)
			uConn := utls.UClient(conn, uConfig, utls.HelloCustom)
			if err := uConn.ApplyPreset(&spec); err != nil {
				return nil, E.Cause(err, "REALITY: apply fingerprint ", id.Str())
			}
			if err := uConn.BuildHandshakeState(); err != nil {
				return nil, err
			}
			return uConn, nil
		}
		if !isRandomized || attempt+1 >= realityReseedAttempts {
			return nil, E.New("REALITY: fingerprint ", id.Str(), " produced a ClientHello without TLS 1.3 key_share; REALITY needs TLS 1.3 (use fingerprint chrome)")
		}
		seed, err := utls.NewPRNGSeed()
		if err != nil {
			return nil, E.Cause(err, "REALITY: reseed randomized fingerprint")
		}
		id.Seed = seed
	}
}

func specHasKeyShare(spec *utls.ClientHelloSpec) bool {
	for _, extension := range spec.Extensions {
		if _, ok := extension.(*utls.KeyShareExtension); ok {
			return true
		}
	}
	return false
}

// ensureMLKEMFirst делает X25519MLKEM768 первым элементом supported_groups и
// key_shares в списке расширений ДО ApplyPreset (см. newRealityUConn). Данные
// share оставляются пустыми — их сгенерирует ApplyPreset. Идемпотентно.
func ensureMLKEMFirst(extensions []utls.TLSExtension) {
	for _, extension := range extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves := common.Filter(ext.Curves, func(id utls.CurveID) bool { return id != utls.X25519MLKEM768 })
			ext.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, curves...)
		case *utls.KeyShareExtension:
			shares := common.Filter(ext.KeyShares, func(ks utls.KeyShare) bool { return ks.Group != utls.X25519MLKEM768 })
			ext.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, shares...)
		}
	}
}
