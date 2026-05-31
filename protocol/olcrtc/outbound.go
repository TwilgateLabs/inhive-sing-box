//go:build with_olcrtc

// Package olcrtc реализует sing-box outbound поверх TwilgateLabs/inhive-olcrtc
// (fork github.com/openlibrecommunity/olcrtc) — stealth tunnel через легальные
// WebRTC SFU (jitsi/wbstream/telemost). См. project_olcrtc_implementation.md
// для полного контекста (3-carrier failover, mode switching, etc).
//
// # Integration pattern: SOCKS5 detour (Pattern A)
//
// Forked `pkg/olcrtc/client` экспортит только blocking `Run(ctx, cfg) error`.
// Внутри:
//  1. Поднимает WebRTC carrier link к SFU
//  2. Делает muxconn (AES-GCM) + smux multiplexing + handshake control stream
//  3. Открывает local SOCKS5 listener (cfg.LocalAddr)
//  4. Блокирует до ctx.Done()
//
// Мы выбрали Pattern A (SOCKS5 detour vs direct smux integration) потому что:
//   - client.Run уже инкапсулирует reconnect / handshake retry / liveness loop —
//     не хотим параллельную реализацию
//   - sing-box's naive outbound тоже использует localhost client + handshake
//     pattern (`cronet-go.NaiveClient` имеет аналогичный internal SOCKS-like layer)
//   - direct smux integration требует второй PR в fork чтобы expose Dial/OpenStream —
//     лишний divergence от upstream
//   - SOCKS5 hop = localhost only, latency overhead ~10-50 µs, security surface
//     ограничена loopback + optional SocksUser/SocksPass auth
//
// # Lifecycle (Вариант C — lazy non-primary)
//
//	NewOutbound        — валидирует option.OLCRTCOutboundOptions; не открывает соединений
//	Start(start)       — primary: launchClient + блокирует до onReady/error/timeout
//	                     (blocking-ready, анти-phantom). non-primary: возвращает nil
//	                     сразу, join откладывается до первого DialContext (lazy).
//	DialContext(ctx)   — ensureStarted (lazy join non-primary при первом dial),
//	                     затем connect к localhost SOCKS5 через sing socks.Client
//	Close()            — отменяет internal ctx; ждёт client.Run done (с timeout)
//	                     только если goroutine реально запускалась
//
// # Hardening
//
//   - SEC-2 (datachannel-only) — enforced в option.go validation
//   - SEC-3 (Quad9 DNS default) — enforced в option.go default
//
// См. memory/security_mitigations_olcrtc_pending.md
package olcrtc

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	olcrtcpkg "github.com/openlibrecommunity/olcrtc/pkg/olcrtc"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// SEC-2: единственный allowed transport. Видео transports (vp8channel/seichannel/
// videochannel) принимают arbitrary frames от других participants в shared SFU
// room → parser bug = client DoS / OOB read. Block at config parse time.
const allowedTransport = "datachannel"

// SEC-3: default DoH endpoint для auth API calls. Quad9 — DNSSEC-validating,
// no logging policy, foreign jurisdiction. Защита от DNS poisoning на
// telemetry beacon endpoint в goolom engine.
const defaultDNSServer = "9.9.9.9:53"

const defaultSocksAddr = "127.0.0.1:0" // ephemeral port

// startTimeout — bound на сколько ждём первого onReady callback от client.Run.
// Сюда вмещаются: ICE candidate gathering (~5-15s typical), SFU signaling
// roundtrips, muxconn handshake, smux control stream auth.
//
// Выбрано 30s: agressive для emergency fallback. Юзер уже на сломанной сети,
// лучше быстрый fail → urltest переключится на следующий outbound → user
// получает feedback быстрее чем "висит". При успехе reconnect внутри client
// уже работает с backoff (300ms..5s).
const startTimeout = 30 * time.Second

// closeTimeout — bound на ожидание выхода из client.Run после cancel().
// client.Run должен выйти быстро (defer c.shutdown() закрывает listener +
// session), но если SFU permanently dead с stuck goroutine, ждать вечно нельзя.
const closeTimeout = 5 * time.Second

// uuidRe валидирует ChannelID. UUID v1/v4/v5 все matched этим regex; client
// никак не проверяет version specifically.
var uuidRe = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

// hexRe валидирует KeyHex — exactly 64 hex chars (32 bytes для AES-256).
var hexRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// hostPortRe валидирует DNSServer — non-empty host + ":port" suffix.
// Не парсим полноценно (allow "host:port" и "[v6]:port") — sing-box
// downstream code сам падёт с понятным err при попытке use.
var hostPortRe = regexp.MustCompile(`^.+:\d+$`)

// registerDefaultsOnce гарантирует что pkg/olcrtc.RegisterDefaults() вызван
// один раз на процесс. Carriers / engines / transports мутабельный global
// registry внутри fork; не хотим double-register panic.
var registerDefaultsOnce sync.Once

// RegisterOutbound регистрирует "olcrtc" outbound type в sing-box registry.
// Вызывается из include/olcrtc_outbound.go (только с build tag with_olcrtc).
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.OLCRTCOutboundOptions](registry, C.TypeOLCRTC, NewOutbound)
}

// Outbound — sing-box adapter. TCP-only by design (UDP не поддерживается
// через олcrtc data channel; users UDP трафика должны иметь другой outbound).
type Outbound struct {
	outbound.Adapter

	logger logger.ContextLogger

	// primary решает start-семантику (Вариант C):
	//   - true  — eager blocking-ready: Start() ждёт readyCh/timeout (анти-phantom).
	//   - false — lazy: Start() возвращает nil сразу, join откладывается до
	//     первого DialContext. Мёртвый non-primary не роняет box-старт.
	primary bool

	cfg         client.Config
	socksAddr   string // resolved 127.0.0.1:PORT after ephemeral port reservation
	socksDialer *socks.Client

	// runCtx + runCancel control the lifetime of client.Run goroutine.
	// Создаются в NewOutbound (привязаны к parent ctx из sing-box dialer chain).
	runCtx    context.Context
	runCancel context.CancelFunc

	// runDone закрывается когда client.Run возвращает. runErr содержит last
	// error от client.Run (защищён runMu).
	runDone chan struct{}
	runMu   sync.Mutex
	runErr  error

	// launchOnce гарантирует что client.RunWithReady goroutine спавнится ровно
	// один раз — из Start() для primary ИЛИ из первого DialContext для lazy
	// non-primary (конкурентные dials идемпотентны).
	launchOnce sync.Once
	// launched (под runMu) = goroutine реально была запущена. Close() ждёт
	// runDone только если launched — иначе для lazy-never-dialed outbound'а
	// runDone никогда не закроется (его закрывает defer в goroutine), и Close
	// зависнет на closeTimeout зря.
	launched bool

	// readyCh closed когда onReady fires первый раз.
	readyCh   chan struct{}
	readyOnce sync.Once
}

// NewOutbound валидирует config. Открытие network handles deferred до Start()
// чтобы parse-time errors давали понятный feedback без side effects.
//
// Validation order:
//  1. Required fields (Carrier, RoomURL, ChannelID, KeyHex)
//  2. Format checks (UUID, hex)
//  3. SEC-2: Transport pin
//  4. SEC-3: DNSServer default + format
//  5. Defaults для optional полей
func NewOutbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.OLCRTCOutboundOptions,
) (adapter.Outbound, error) {
	if options.Carrier == "" {
		return nil, E.New("carrier is required for olcrtc outbound")
	}
	if options.RoomURL == "" {
		return nil, E.New("room_url is required for olcrtc outbound")
	}
	if options.ChannelID == "" {
		return nil, E.New("channel_id is required for olcrtc outbound")
	}
	if !uuidRe.MatchString(options.ChannelID) {
		return nil, E.New("channel_id must be a UUID (got ", options.ChannelID, ")")
	}
	if options.KeyHex == "" {
		return nil, E.New("key_hex is required for olcrtc outbound")
	}
	if !hexRe.MatchString(options.KeyHex) {
		return nil, E.New("key_hex must be exactly 64 hex chars (32 bytes)")
	}

	// SEC-2: hard-pin transport=datachannel. Block video transports.
	transport := options.Transport
	if transport == "" {
		transport = allowedTransport
	}
	if transport != allowedTransport {
		return nil, E.New(
			"transport=", transport,
			" is not permitted (SEC-2 video transports blocked); ",
			"only \"datachannel\" allowed",
		)
	}

	// SEC-3: default Quad9 DNS, validate host:port format if user-supplied.
	dnsServer := options.DNSServer
	if dnsServer == "" {
		dnsServer = defaultDNSServer
	} else if !hostPortRe.MatchString(dnsServer) {
		return nil, E.New("dns_server must be in host:port form (got ", dnsServer, ")")
	}

	socksAddr := options.SocksAddr
	if socksAddr == "" {
		socksAddr = defaultSocksAddr
	}

	// Reserve an ephemeral port if user asked for :0 — client.Run() doesn't
	// surface the resolved listener address via onReady, so we must know it
	// before starting. Race window between Close()/Listen() is <1ms localhost;
	// acceptable per-package precedent (e.g. tests routinely do this).
	resolvedAddr, err := resolveLocalAddr(socksAddr)
	if err != nil {
		return nil, E.Cause(err, "reserve local socks addr")
	}

	// Mutable global within fork. Idempotent per upstream test
	// (TestRegisterDefaults_Idempotent), but still guard with sync.Once to
	// keep startup deterministic.
	registerDefaultsOnce.Do(olcrtcpkg.RegisterDefaults)

	cfg := client.Config{
		Transport: allowedTransport,
		Carrier:   options.Carrier,
		RoomURL:   options.RoomURL,
		ChannelID: options.ChannelID,
		KeyHex:    options.KeyHex,
		LocalAddr: resolvedAddr,
		DNSServer: dnsServer,
		SOCKSUser: options.SocksUser,
		SOCKSPass: options.SocksPass,
		Engine:    options.Engine,
		URL:       options.URL,
		Token:     options.Token,
		// Liveness / TransportOptions / Traffic / Claims left as zero — client
		// will use its built-in defaults (control.Default{Interval,Timeout,Failures}
		// and the right TransportOptions for "datachannel").
		DeviceID: options.ChannelID, // ChannelID = device identity по smaller-API design
	}

	// Привязываем internal ctx к sing-box dialer chain ctx чтобы при teardown
	// всей цепочки наш goroutine тоже умер. NewOutbound's ctx — request-scoped
	// для creation, но manager pinned его lifetime через DialerOptions; pattern
	// см. в naive/outbound.go: NaiveClient hangs onto ctx так же.
	runCtx, runCancel := context.WithCancel(ctx)

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(
			C.TypeOLCRTC, tag, []string{N.NetworkTCP}, options.DialerOptions,
		),
		logger:    logger,
		primary:   options.Primary,
		cfg:       cfg,
		socksAddr: resolvedAddr,
		runCtx:    runCtx,
		runCancel: runCancel,
		runDone:   make(chan struct{}),
		readyCh:   make(chan struct{}),
	}, nil
}

// resolveLocalAddr returns the original addr if a non-zero port is set,
// or reserves+releases an ephemeral port and returns "127.0.0.1:PORT" otherwise.
// Race window: <1ms typical, localhost only.
func resolveLocalAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("split %q: %w", addr, err)
	}
	if port != "0" {
		return addr, nil
	}
	// Bind, capture port, release — кто-то может schvatить за это окно, но на
	// loopback risk acceptable (no untrusted local processes in our threat
	// model; if there were, SocksUser/SocksPass would mitigate).
	ln, err := net.Listen("tcp4", net.JoinHostPort(host, "0"))
	if err != nil {
		return "", fmt.Errorf("listen ephemeral: %w", err)
	}
	resolved := ln.Addr().String()
	if cerr := ln.Close(); cerr != nil {
		return "", fmt.Errorf("close ephemeral: %w", cerr)
	}
	return resolved, nil
}

// Start реализует Вариант C (lazy non-primary).
//
//   - primary==true → eager blocking-ready: спавним client.RunWithReady и
//     блокируем Start() до readyCh / permanent error / timeout. Когда Start()
//     возвращает nil, SOCKS5 detour гарантированно поднят. Это анти-phantom
//     инвариант: на iOS NE применяет TUN routes как только box ready, поэтому
//     ВЫБРАННЫЙ канал обязан быть готов до того (откатывали 2e288c2d).
//
//   - primary==false → LAZY: Start() возвращает nil НЕМЕДЛЕННО, НЕ спавнит
//     goroutine, НЕ блокирует. Join в Jitsi откладывается до первого
//     DialContext. Так мёртвый невыбранный pool-member не может уронить
//     box-старт через timeout (manager.startOutbounds падает на любой Start()
//     error). Эталон — WireGuard endpoint: Start не блокирует на handshake,
//     connect происходит на первом пакете.
//
// На permanent error (client.Run возвращает раньше onReady): outbound остаётся
// зарегистрированным но DialContext будет возвращать last err. Sing-box
// urltest пометит outbound unhealthy.
func (o *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	if !o.primary {
		// Lazy: никакой network activity на старте. Готовим SOCKS5 dialer
		// заранее (он не открывает соединений — connect происходит в его
		// DialContext), а join поднимем при первом dial.
		o.logger.Info("olcrtc client lazy (non-primary, join deferred to first dial; carrier=", o.cfg.Carrier, " socks=", o.socksAddr, ")")
		o.socksDialer = o.newSocksDialer()
		return nil
	}

	o.logger.Info("starting olcrtc client (primary, carrier=", o.cfg.Carrier, " socks=", o.socksAddr, ")")
	o.launchClient()

	if err := o.awaitReady(startTimeout); err != nil {
		return err
	}
	o.logger.Info("olcrtc client ready (SOCKS5 listener up on ", o.socksAddr, ")")
	o.socksDialer = o.newSocksDialer()
	return nil
}

// launchClient спавнит управляемую client.RunWithReady goroutine ровно один
// раз (launchOnce). Вызывается из Start() для primary и из первого DialContext
// для lazy non-primary.
func (o *Outbound) launchClient() {
	o.launchOnce.Do(func() {
		o.runMu.Lock()
		o.launched = true
		o.runMu.Unlock()
		go func() {
			defer close(o.runDone)
			err := client.RunWithReady(o.runCtx, o.cfg, o.onReady)
			o.runMu.Lock()
			o.runErr = err
			o.runMu.Unlock()
			if err != nil && o.runCtx.Err() == nil {
				o.logger.Error("olcrtc client exited: ", err)
			}
		}()
	})
}

// awaitReady блокирует до readyCh / runDone (early exit = failure) / timeout.
// Используется blocking-path'ом primary Start() и lazy-path'ом первого dial.
func (o *Outbound) awaitReady(timeout time.Duration) error {
	select {
	case <-o.readyCh:
		return nil
	case <-o.runDone:
		// client.Run возвратился до того как onReady fired — это всегда
		// failure (либо bringUpLink упал, либо listener.Listen errorнул,
		// либо ctx был cancelled между ними). Если onReady технически
		// fired ровно в этот же tick (race), мы всё равно правильно
		// fail'имся: client уже dead, listener закрыт его defer'ом,
		// socksDialer был бы useless.
		o.runMu.Lock()
		err := o.runErr
		o.runMu.Unlock()
		if err == nil {
			err = E.New("olcrtc client exited before ready")
		}
		return E.Cause(err, "olcrtc client start")
	case <-time.After(timeout):
		o.logger.Warn("olcrtc client start timed out after ", timeout, " — cancelling")
		o.runCancel()
		// Не ждём runDone здесь — Close() сделает proper cleanup. Start error
		// → manager пометит outbound failed.
		return E.New("olcrtc client start timed out after ", timeout)
	}
}

// newSocksDialer строит SOCKS5 client поверх plain loopback dialer. Не
// использует sing-box dialer — соединение чисто localhost (наш собственный
// listener), не должно проходить routing / DNS / interfaces. Сам по себе
// connection не открывает (это делает его DialContext).
func (o *Outbound) newSocksDialer() *socks.Client {
	return socks.NewClient(
		directLoopbackDialer{},
		M.ParseSocksaddr(o.socksAddr),
		socks.Version5,
		o.cfg.SOCKSUser,
		o.cfg.SOCKSPass,
	)
}

// onReady передаётся в client.RunWithReady. Может быть вызван более одного
// раза если client делает reconnect — мы фиксируем только первый.
func (o *Outbound) onReady() {
	o.readyOnce.Do(func() {
		close(o.readyCh)
	})
}

// DialContext тунелирует через локальный SOCKS5 listener поднятый client.Run.
//
// Для primary client уже ready после Start(). Для lazy non-primary первый dial
// запускает join (idempotent через launchOnce) и ждёт readyCh с startTimeout —
// это и есть "connect on first packet". Если join fail — ошибка возвращается
// этому dial'у (urltest пометит outbound unhealthy), НИЧЕГО глобально не
// роняется.
func (o *Outbound) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if err := o.ensureStarted(ctx); err != nil {
			return nil, err
		}
		// Fast path: если client уже умер, не делаем futile dial.
		o.runMu.Lock()
		runErr := o.runErr
		o.runMu.Unlock()
		if runErr != nil {
			return nil, E.Cause(runErr, "olcrtc client dead")
		}
		if o.socksDialer == nil {
			return nil, E.New("olcrtc not started")
		}
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		return o.socksDialer.DialContext(ctx, network, destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

// ensureStarted — lazy trigger для non-primary. Для primary (или уже
// запущенного non-primary) это дешёвый no-op: launchOnce уже сработал и readyCh
// закрыт, так что awaitReady возвращается немедленно. Для первого dial'а на
// lazy outbound — спавнит join и ждёт ready с startTimeout. Bounded ctx dial'а
// здесь не используется как deadline join'а намеренно: join (ICE+SFU+smux) может
// быть дольше одного HTTP-запроса, startTimeout — собственный bound (как у
// primary Start()).
func (o *Outbound) ensureStarted(ctx context.Context) error {
	o.runMu.Lock()
	launched := o.launched
	o.runMu.Unlock()
	if launched {
		// Goroutine уже бежит (primary или ранее разбуженный non-primary).
		// Если она ещё не ready — подождём (последующий конкурентный dial).
		// На уже закрытом readyCh это мгновенно.
		select {
		case <-o.readyCh:
			return nil
		default:
			return o.awaitReady(startTimeout)
		}
	}
	// Первый dial на lazy non-primary: поднимаем join сейчас.
	o.logger.InfoContext(ctx, "olcrtc lazy join on first dial (carrier=", o.cfg.Carrier, ")")
	o.launchClient()
	return o.awaitReady(startTimeout)
}

// ListenPacket — UDP не поддерживается. WebRTC data channel = reliable+ordered,
// UDP datagram semantic несовместима. Users UDP трафика должны иметь другой
// outbound в маршрутах.
func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("UDP is not supported by olcrtc outbound")
}

// Close cancellит client.Run context и ждёт его выхода с timeout. Если client
// застрял в shutdown — логим warn и возвращаем nil чтобы не блочить sing-box.
//
// Lazy non-primary который ни разу не диалили: goroutine не запускалась, runDone
// никогда не закроется (его закрывает defer в goroutine). runCancel() всё равно
// зовём (отменяет runCtx для порядка — idempotent, без эффекта если goroutine
// не было), но НЕ ждём runDone — иначе Close висел бы closeTimeout зря на каждом
// невыбранном pool-member.
func (o *Outbound) Close() error {
	o.runCancel()
	o.runMu.Lock()
	launched := o.launched
	o.runMu.Unlock()
	if !launched {
		return nil
	}
	select {
	case <-o.runDone:
		// clean exit
	case <-time.After(closeTimeout):
		o.logger.Warn("olcrtc client did not exit within ", closeTimeout, " of Close()")
	}
	return nil
}

// directLoopbackDialer — minimal N.Dialer для socks.Client. Не использует
// dialer.Default или dialer chain потому что:
//   - destination всегда localhost (наш собственный listener)
//   - не хотим recursive routing (loopback → routes → outbound → loopback)
//   - DNS lookup не нужен (IP-literal address)
//
// Compile-time check N.Dialer interface match.
var _ N.Dialer = directLoopbackDialer{}

type directLoopbackDialer struct{}

func (directLoopbackDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, destination.String())
}

// ListenPacket для socks.Client теоретически нужен для UDP ASSOCIATE flow,
// но мы не делаем UDP (см. Outbound.ListenPacket). Возвращаем error чтобы
// случайные code paths не openали неожиданный UDP socket.
func (directLoopbackDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("olcrtc loopback dialer does not support UDP")
}

// Compile-time interface checks.
var _ adapter.Outbound = (*Outbound)(nil)
