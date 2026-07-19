package xhttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/buf"
	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/common/xray/net"
	"github.com/sagernet/sing-box/common/xray/pipe"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	"github.com/sagernet/sing-box/common/xray/uuid"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/http2"
	"golang.org/x/sync/semaphore"
)

type Client struct {
	ctx            context.Context
	options        *option.V2RayXHTTPOptions
	mode           string // resolved dial mode ("auto" is resolved at construction, per Xray semantics)
	getRequestURL  func(sessionId string) url.URL
	getRequestURL2 func(sessionId string) url.URL
	getHTTPClient  func() (DialerClient, *XmuxClient)
	getHTTPClient2 func() (DialerClient, *XmuxClient)

	// uploadBudget ограничивает СУММАРНЫЕ байты upload-POST'ов в полёте по ВСЕМ
	// соединениям этого сервера. Без него каждое проксируемое TCP-соединение
	// шлёт аплинк своей goroutine'ой без cross-connection лимита — под нагрузкой
	// (лента = десятки соединений) в полёте копятся десятки `http2.writeRequestBody`
	// по ~sc_max_each_post_bytes каждый (24MB в device-heap-профиле iOS, 56% всей
	// памяти → jetsam при 50MB-лимите NE). Вес = байты чанка → мелкие посты идут
	// параллельно (throughput не режется), блокируется только спайк крупных.
	// nil = без лимита (не-iOS: RAM есть, важнее пропускная).
	uploadBudget     *semaphore.Weighted
	uploadBudgetSize int64

	// streamSlots ограничивает ЧИСЛО одновременных xhttp-стримов (соединений)
	// на iOS. Каждый открытый стрим держит http2 write scratch-буфер размера
	// min(серверный SETTINGS_MAX_FRAME_SIZE, 512KB) ВСЁ время жизни (для
	// stream-one/stream-up — до закрытия соединения). Сервер, объявляющий
	// большой frame size (дефолт xray xhttp = 1MB → 512KB/стрим), × десятки
	// параллельных соединений под лентой = 40MB внутри ~50MB NE-бюджета →
	// jetsam (device-подтверждено 2026-07-17: 512KB×77 стримов = 39.7MB).
	// Размер буфера диктует СЕРВЕР и клиент его не уменьшает без форка x/net —
	// поэтому единственный клиентский рычаг против ЛЮБОГО (в т.ч. чужого кривого)
	// сервера = лимит ЧИСЛА буферов. Буферизованный канал = counting-семафор;
	// nil на не-iOS (без лимита). Acquire в DialContext = backpressure на новые
	// соединения, Release в onClose.
	streamSlots chan struct{}
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	// Resolve the dial mode up front. Xray treats an empty mode and mode:"auto"
	// identically (GetNormalizedMode), and our subscription parser (xray2sing)
	// defaults xhttp mode to "auto" — so most real configs arrive as "auto".
	// Our fork lacked GetNormalizedMode, so "auto"/"" fell through DialContext's
	// stream-one/stream-up checks straight into the packet-up POST loop, while
	// Xray's own auto picks stream-one for REALITY. That mismatch left every
	// reality-xhttp config dead. Resolve here, once, using Xray's semantics.
	resolvedMode := resolveXHTTPMode(options.Mode, tlsConfig, options.Download)
	dest := serverAddr
	baseRequestURL, err := getBaseRequestURL(
		&options.V2RayXHTTPBaseOptions, dest, tlsConfig,
	)
	if err != nil {
		return nil, err
	}
	getRequestURL := func(sessionId string) url.URL {
		requestURL := baseRequestURL
		applySessionPlacement(&requestURL, &options.V2RayXHTTPBaseOptions, sessionId)
		return requestURL
	}
	var xmuxOptions option.V2RayXHTTPXmuxOptions
	if options.Xmux != nil {
		xmuxOptions = *options.Xmux
	}
	if xmuxOptions == (option.V2RayXHTTPXmuxOptions{}) {
		applyXmuxDefaults(&xmuxOptions)
	}
	xmuxManager := NewXmuxManager(xmuxOptions, func() XmuxConn {
		return createHTTPClient(dest, dialer, &options.V2RayXHTTPBaseOptions, tlsConfig)
	})
	getHTTPClient := func() (DialerClient, *XmuxClient) {
		xmuxClient := xmuxManager.GetXmuxClient(ctx)
		return xmuxClient.XmuxConn.(DialerClient), xmuxClient
	}
	getRequestURL2 := getRequestURL
	getHTTPClient2 := getHTTPClient
	if options.Download != nil {
		options2 := options.Download
		dialer2 := dialer
		if options2.Detour != "" {
			var ok bool
			dialer2, ok = service.FromContext[adapter.OutboundManager](ctx).Outbound(options2.Detour)
			if !ok {
				return nil, E.New("outbound detour not found: ", options2.Detour)
			}
		}
		dest2 := options2.ServerOptions.Build()
		var tlsConfig2 tls.Config
		if options2.TLS != nil {
			tlsConfig2, err = tls.NewClient(ctx, logger.NOP(), options2.Server, common.PtrValueOrDefault(options2.TLS))
			if err != nil {
				return nil, err
			}
		}
		baseRequestURL2, err := getBaseRequestURL(&options2.V2RayXHTTPBaseOptions, dest2, tlsConfig2)
		if err != nil {
			return nil, err
		}
		getRequestURL2 = func(sessionId string) url.URL {
			requestURL2 := baseRequestURL2
			applySessionPlacement(&requestURL2, &options2.V2RayXHTTPBaseOptions, sessionId)
			return requestURL2
		}
		var xmuxOptions2 option.V2RayXHTTPXmuxOptions
		if options2.Xmux != nil {
			xmuxOptions2 = *options2.Xmux
		}
		// InHive 2026-07-19: тот же дефолтинг, что и для аплинка выше. У Xray он
		// применяется автоматически, т.к. downloadSettings собирается тем же
		// Build() рекурсивно (infra/conf/transport_method.go — `c.DownloadSettings.Build()`),
		// а у нас блок был продублирован только для upload-ветки. Без этого
		// stream-down половина сессии (весь ПРИЁМ) ехала на Go-нулях с той же
		// патологией «безлимит стримов в одно неротируемое соединение».
		if xmuxOptions2 == (option.V2RayXHTTPXmuxOptions{}) {
			applyXmuxDefaults(&xmuxOptions2)
		}
		xmuxManager2 := NewXmuxManager(xmuxOptions2, func() XmuxConn {
			return createHTTPClient(dest2, dialer2, &options2.V2RayXHTTPBaseOptions, tlsConfig2)
		})
		getHTTPClient2 = func() (DialerClient, *XmuxClient) {
			xmuxClient2 := xmuxManager2.GetXmuxClient(ctx)
			return xmuxClient2.XmuxConn.(DialerClient), xmuxClient2
		}
	}
	client := &Client{
		ctx:            ctx,
		options:        &options,
		mode:           resolvedMode,
		getHTTPClient:  getHTTPClient,
		getHTTPClient2: getHTTPClient2,
		getRequestURL:  getRequestURL,
		getRequestURL2: getRequestURL2,
	}
	// uploadBudget И streamSlots — ОБА ОТКЛЮЧЕНЫ (2026-07-18). Поля + nil-guarded
	// Acquire/Release в DialContext оставлены (no-op), чтобы вернуть с
	// НЕ-throttling редизайном, если понадобится.
	//
	// uploadBudget (8MB byte-семафор upload-POST'ов, был только iOS) снят по
	// device-замеру на packet-up CDN-конфиге (Никита, LTE, build 126): отдача
	// 1.3 Мбит/с у нас против 91 у Happ на ТОМ ЖЕ конфиге (пинг 644 против 191).
	// Это ЕДИНСТВЕННЫЙ поведенческий дифф нашего packet-up-пути от Happ. Механизм:
	// бюджет ГЛОБАЛЬНЫЙ на сервер (per-Client), а Release стоит в горутине ПОСЛЕ
	// возврата PostPacket, который на CDN-пути строится с context.WithoutCancel и
	// без таймаута (dialer.go:92) → зависший POST не возвращает свой ≤1MB в пул →
	// накопление → пул к нулю → все новые Acquire (в т.ч. DNS-в-туннеле и h2
	// WINDOW_UPDATE проксируемой сессии) блокируются → отдача душится, скачивание
	// встаёт «на половине», спидтест 00, «свитч конфига лечит» (свежий Client =
	// свежий пул) — классическая утечка. Happ бюджета не имеет → N параллельных
	// packet-up-аплоадов летят свободно (xmux у CDN-конфигов не задан, параллель
	// даёт сам спидтест N соединениями). Память, ради которой ставился бюджет:
	// (1) реальный хог — stream-mode writeRequestBody (512KB×N), НЕ packet-up
	// (бюджет стоял не там); (2) per-connection upload-pipe уже кэпит packet-up
	// (~1MB, pipe.WithSizeLimit ниже в DialContext); (3) спайки ловит oomkiller
	// (120) + circuit-breaker (123) + mixed-стек (126). Тот же разбор снял
	// streamSlots в 125 — это его близнец, оставленный тогда живым по недосмотру.
	// client.uploadBudget = semaphore.NewWeighted(budget) // НЕ инициализируем
	// client.streamSlots  = make(chan struct{}, N)        // НЕ инициализируем
	return client, nil
}

// applyXmuxDefaults подставляет дефолты Xray для ОТСУТСТВУЮЩЕГО блока `xmux`.
//
// Xray делает это в конфиг-парсере (infra/conf/transport_method.go,
// `if c.Xmux == (XmuxConfig{})`), который мы не портировали — рантайм перенесли,
// дефолтинг нет. Без него конфиг без `xmux` (все наши CDN-бэкенды: рендерер
// отдаёт xhttp_extra дословно и блок теряется) ехал на Go-нулях
// concurrency=0/connections=0/hMaxRequestTimes=0, что в GetXmuxClient означает
// «безлимит стримов в ОДНО никогда не ротируемое соединение». Против эджа,
// анонсирующего MAX_CONCURRENT_STREAMS=128, это соединение насыщается и эдж
// начинает рубить стримы (INTERNAL_ERROR) — отдача стартует сотнями Мбит/с и
// схлопывается до ~0.5 в пределах одного спидтеста.
//
// ⚠️ Значения сверены с Xray 26.7.11 (актуальный апстрим, из которого собран
// референсный клиент Happ), а НЕ с 26.1.13, по которому делалась первая версия
// этой правки. Апстрим сменил дефолт между этими версиями:
//
//	26.1.13: MaxConcurrency = 1..1     ← было у нас; соединение НА КАЖДЫЙ стрим
//	26.7.11: MaxConnections = 6..6     ← сейчас; пул из 6 соединений, стримы
//	                                     распределяются по ним (concurrency=0)
//
// Разница принципиальная для стабильности: при concurrency=1 каждое проксируемое
// TCP-соединение тянет СВОЙ TLS-хендшейк через CDN (спидтест открывает их
// десятками → шторм хендшейков, каждое соединение стартует с холодного
// congestion window), при connections=6 работает тёплый пул фиксированного
// размера в устоявшемся режиме. Именно это отличает ровный Happ от нашей
// «метастабильности» (приём гулял 222→47 при отдаче 0.5-0.75).
//
// maxConnections и maxConcurrency у Xray взаимоисключающие
// (infra/conf/transport_method.go:449 — конфиг с обоими отвергается), поэтому
// здесь выставляется РОВНО одно из них.
func applyXmuxDefaults(x *option.V2RayXHTTPXmuxOptions) {
	x.MaxConnections = Xbadoption.Range{From: 6, To: 6}
	x.HMaxRequestTimes = Xbadoption.Range{From: 600, To: 900}
	x.HMaxReusableSecs = Xbadoption.Range{From: 1800, To: 3000}
}

// resolveXHTTPMode maps the configured mode to a concrete dial mode, mirroring
// Xray-core's dialer.go auto logic:
//
//	mode = "packet-up"
//	if reality != nil { mode = "stream-one"; if downloadSettings != nil { mode = "stream-up" } }
//
// Only "auto" (and empty, which Xray treats as auto) is resolved; an explicitly
// configured mode (stream-one / stream-up / packet-up / stream-down) is returned
// unchanged so existing configs keep their exact behaviour. For a non-reality
// auto config the result is "packet-up" — identical to today's fall-through, so
// no regression for plain xhttp; the fix only changes reality-xhttp, which Xray
// dials as stream-one and we previously (wrongly) dialed as packet-up.
func resolveXHTTPMode(mode string, tlsConfig tls.Config, download *option.V2RayXHTTPDownloadOptions) string {
	if mode != "" && mode != "auto" {
		return mode
	}
	if tlsConfig != nil && tls.IsRealityClientConfig(tlsConfig) {
		if download != nil {
			return "stream-up"
		}
		return "stream-one"
	}
	return "packet-up"
}

func (c *Client) DialContext(ctx context.Context) (retConn net.Conn, retErr error) {
	options := c.options
	mode := c.mode // resolved at construction ("auto"/"" already mapped to a concrete mode)
	// iOS: занять слот стрима ДО открытия соединения. Блокировка здесь =
	// backpressure на роутер (новое соединение ждёт, а не плодит буфер). Слот
	// освобождается в onClose (успех) или дефером ниже (любой ошибочный
	// return — retConn остаётся nil). См. поле streamSlots.
	if c.streamSlots != nil {
		select {
		case c.streamSlots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var slotOnce sync.Once
	releaseSlot := func() {
		if c.streamSlots != nil {
			slotOnce.Do(func() { <-c.streamSlots })
		}
	}
	defer func() {
		if retConn == nil {
			releaseSlot()
		}
	}()
	sessionIdUuid := uuid.New()
	requestURL := c.getRequestURL(sessionIdUuid.String())
	requestURL2 := c.getRequestURL2(sessionIdUuid.String())
	httpClient, xmuxClient := c.getHTTPClient()
	httpClient2, xmuxClient2 := c.getHTTPClient2()
	if xmuxClient != nil {
		xmuxClient.OpenUsage.Add(1)
	}
	if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
		xmuxClient2.OpenUsage.Add(1)
	}
	var closed atomic.Int32
	// InHive 2026-07-19: контекст ЖИЗНИ СОЕДИНЕНИЯ.
	//
	// WithoutCancel отвязывает от dial-контекста (он отменяется сразу после
	// возврата из DialContext — ровно поэтому апстрим Xray оборачивает каждый
	// запрос в context.WithoutCancel), WithCancel возвращает нам владение: cancel
	// стоит в onClose. Итог — запросы переживают завершение дозвона, но умирают
	// при закрытии проксируемого conn.
	//
	// Это замена снятых сегодня ctx-костылей (`select { <-ctx.Done() }` в цикле
	// отправки и ctx-проверки в WaitReadCloser.Read). Те привязывались к
	// DIAL-контексту, то есть срабатывали почти сразу и не по делу: ломали
	// упорядоченность seq в аплинке и рвали download-стрим, оставляя
	// upload-горутину жить — сессия наполовину мертва. Здесь же lifetime привязан
	// к тому единственному событию, которое действительно делает запрос
	// бессмысленным.
	uploadCtx, uploadCancel := context.WithCancel(context.WithoutCancel(ctx))
	reader, writer := io.Pipe()
	conn := splitConn{
		writer: writer,
		onClose: func() {
			if closed.Add(1) > 1 {
				return
			}
			uploadCancel()
			releaseSlot()
			if xmuxClient != nil {
				xmuxClient.OpenUsage.Add(-1)
			}
			if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
				xmuxClient2.OpenUsage.Add(-1)
			}
		},
	}
	// Ошибочный возврат ниже означает, что conn.onClose уже никогда не вызовется —
	// отменяем conn-контекст здесь, иначе он (и его горутины) утекут.
	defer func() {
		if retConn == nil {
			uploadCancel()
		}
	}()
	var err error
	if mode == "stream-one" {
		requestURL.Path = options.GetNormalizedPath()
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient.OpenStream(uploadCtx, requestURL.String(), reader, false)
		if err != nil { // browser dialer only
			return nil, err
		}
		return &conn, nil
	} else { // stream-down
		if xmuxClient2 != nil {
			xmuxClient2.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient2.OpenStream(uploadCtx, requestURL2.String(), nil, false)
		if err != nil { // browser dialer only
			return nil, err
		}
	}
	if mode == "stream-up" {
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		_, _, _, err = httpClient.OpenStream(uploadCtx, requestURL.String(), reader, true)
		if err != nil { // browser dialer only
			return nil, err
		}
		return &conn, nil
	}
	scMaxEachPostBytes := options.GetNormalizedScMaxEachPostBytes()
	scMinPostsIntervalMs := options.GetNormalizedScMinPostsIntervalMs()
	if scMaxEachPostBytes.From <= buf.Size {
		// inhive: malformed server config (sc_max_each_post_bytes <= 8192) must
		// never panic the whole process. Return an error so the bad outbound
		// degrades to a failed dial instead of aborting the VPN service.
		return nil, E.New("`scMaxEachPostBytes` should be bigger than ", buf.Size)
	}
	maxUploadSize := scMaxEachPostBytes.Rand()
	// WithSizeLimit(0) will still allow single bytes to pass, and a lot of
	// code relies on this behavior. Subtract 1 so that together with
	// uploadWriter wrapper, exact size limits can be enforced
	// uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - 1))
	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - buf.Size))
	conn.writer = uploadWriter{
		uploadPipeWriter,
		maxUploadSize,
	}
	go func() {
		var seq int64
		var lastWrite time.Time
		// InHive 2026-07-19: локальные копии клиента вместо переиспользования
		// переменных внешней функции — фикс ГОНКИ ДАННЫХ, сделанный в апстриме
		// Xray 26.7.11 (splithttp/dialer.go: dynamicHTTPClient/dynamicXmuxClient
		// + передача hClient ПАРАМЕТРОМ в горутину). До него (и у нас) ротация
		// `httpClient, xmuxClient = c.getHTTPClient()` писала в те же переменные,
		// которые ПАРАЛЛЕЛЬНО читают уже запущенные POST-горутины: незащищённая
		// запись/чтение interface-значения. Практический эффект — POST мог уехать
		// не в то соединение, которое ему выдал менеджер (а с hMaxRequestTimes
		// 600-900 при ~33 POST/с ротация приходится ровно на середину спидтеста).
		dynamicHTTPClient := httpClient
		dynamicXmuxClient := xmuxClient
		for {
			wroteRequest := done.New()
			ctx := httptrace.WithClientTrace(uploadCtx, &httptrace.ClientTrace{
				WroteRequest: func(httptrace.WroteRequestInfo) {
					wroteRequest.Close()
				},
			})
			// this intentionally makes a shallow-copy of the struct so we
			// can reassign Path (potentially concurrently)
			url := requestURL
			applySeqPlacement(&url, &options.V2RayXHTTPBaseOptions, seq)
			seq += 1
			if scMinPostsIntervalMs.From > 0 {
				time.Sleep(time.Duration(scMinPostsIntervalMs.Rand())*time.Millisecond - time.Since(lastWrite))
			}
			// by offloading the uploads into a buffered pipe, multiple conn.Write
			// calls get automatically batched together into larger POST requests.
			// without batching, bandwidth is extremely limited.
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}
			// InHive instrumentation (TEMPORARY, see chunkhist.go): the size handed to
			// each POST is what caps packet-up throughput (chunk * ~33 POSTs/s).
			recordPostChunk(int(chunk.Len()))
			lastWrite = time.Now()
			if dynamicXmuxClient != nil && (dynamicXmuxClient.LeftRequests.Add(-1) <= 0 ||
				(dynamicXmuxClient.UnreusableAt != time.Time{} && lastWrite.After(dynamicXmuxClient.UnreusableAt))) {
				dynamicHTTPClient, dynamicXmuxClient = c.getHTTPClient()
			}
			// Байтовый бюджет upload-байт в полёте (iOS). Acquire ЗДЕСЬ (в цикле,
			// не в goroutine) = backpressure на pipe→TUN, а не дроп: при упоре в
			// бюджет цикл ждёт, TUN притормаживает отправителя. Вес клампим к
			// потолку (страховка от Acquire(n>size)-вечной блокировки). Release —
			// в goroutine после возврата PostPacket (chunk + h2-стрим живут до
			// ответа сервера).
			var acquired int64
			if c.uploadBudget != nil {
				acquired = int64(chunk.Len())
				if acquired > c.uploadBudgetSize {
					acquired = c.uploadBudgetSize
				}
				if err := c.uploadBudget.Acquire(ctx, acquired); err != nil {
					buf.ReleaseMulti(chunk)
					break
				}
			}
			// hClient передаётся ПАРАМЕТРОМ (parity с Xray 26.7.11): горутина обязана
			// работать с тем клиентом, который был актуален на момент её запуска, а
			// не с тем, на который переменную успела перезаписать ротация.
			go func(hClient DialerClient) {
				err := hClient.PostPacket(
					ctx,
					url.String(),
					&buf.MultiBufferContainer{MultiBuffer: chunk},
					int64(chunk.Len()),
				)
				if c.uploadBudget != nil {
					c.uploadBudget.Release(acquired)
				}
				wroteRequest.Close()
				if err != nil {
					// InHive 2026-07-19: до этой строки отказ POST'а НИГДЕ не
					// фиксировался — Interrupt() молча убивал upload-половину, а
					// апстрим Xray в этом месте пишет
					// errors.LogInfoInner(ctx, err, "failed to send upload").
					// Из-за пропажи этого лога отсутствие строк про non-200 в
					// box.log ошибочно читалось как «отказов нет», хотя
					// access-лог origin их показывал. Logger'а в конструкторе
					// транспорта нет, поэтому считаем счётчиками (chunkhist.go),
					// которые сэмплер выводит и в box.log.
					recordUploadError(err)
					uploadPipeReader.Interrupt()
				}
			}(dynamicHTTPClient)
			if _, ok := dynamicHTTPClient.(*DefaultDialerClient); ok {
				// InHive 2026-07-19: возвращена безусловная семантика Xray
				// (splithttp/dialer.go — `<-wroteRequest.Wait()`).
				//
				// Был `select { <-ctx.Done(); <-wroteRequest.Wait() }` — правка без
				// обоснования, и она ЛОМАЕТ ПРОТОКОЛ: packet-up нумерует POST'ы `seq`,
				// а приёмная сторона (upload_queue) собирает их СТРОГО ПО ПОРЯДКУ,
				// буферизуя не более scMaxBufferedPosts. Ожидание здесь — единственное,
				// что сериализует отправку. При отменённом ctx оно переставало ждать, и
				// цикл начинал выстреливать POST'ы внахлёст на каждый ReadMultiBuffer →
				// порядок на проводе рушился → сервер вставал головой очереди → отдача
				// умирала, а следом и ПРИЁМ (ACK'и проксируемого TCP едут теми же
				// POST'ами) — отсюда наблюдаемая метастабильность: приём гулял 222→47
				// при отдаче 0.5-0.75, тогда как Happ на идентичном конфиге ровно
				// держит 316/279.
				//
				// Защита от зависшего PostPacket сделана там, где ей место — в
				// lifetime самого запроса: он строится на uploadCtx (контекст жизни
				// conn, отменяется в onClose), см. комментарий у uploadCtx выше и в
				// dialer.go. Цена прежней «защиты» здесь была — поломка
				// упорядоченности, то есть лечили симптом ценой протокола.
				<-wroteRequest.Wait()
			}
		}
	}()
	return &conn, nil
}

func (c *Client) Close() error {
	return nil
}

// applySessionPlacement writes the session id into the request URL according to the
// configured placement. Default ("" => path) is byte-identical to the original code
// (requestURL.Path += sessionId). For query placement it is added as a query param; for
// header/cookie placement it is stashed in the URL fragment (stripped from the wire by
// net/http) and relocated to the real header/cookie by GetRequestHeader.
func applySessionPlacement(u *url.URL, options *option.V2RayXHTTPBaseOptions, sessionId string) {
	switch options.GetNormalizedSessionPlacement() {
	case "query":
		q := u.Query()
		q.Set(options.GetNormalizedSessionKey(), sessionId)
		u.RawQuery = q.Encode()
	case "header", "cookie":
		stashMetaFragment(u, option.XHTTPMetaSessionKey(), sessionId)
	default: // "path"
		u.Path += sessionId
	}
}

// applySeqPlacement writes the per-request sequence integer into the request URL.
// Default ("" => path) is byte-identical to the original code
// (url.Path += "/" + strconv.FormatInt(seq, 10)).
func applySeqPlacement(u *url.URL, options *option.V2RayXHTTPBaseOptions, seq int64) {
	seqStr := strconv.FormatInt(seq, 10)
	switch options.GetNormalizedSeqPlacement() {
	case "query":
		q := u.Query()
		q.Set(options.GetNormalizedSeqKey(), seqStr)
		u.RawQuery = q.Encode()
	case "header", "cookie":
		stashMetaFragment(u, option.XHTTPMetaSeqKey(), seqStr)
	default: // "path"
		u.Path += "/" + seqStr
	}
}

// stashMetaFragment merges a key=value pair into the URL fragment without dropping any
// pair already present (e.g. session id stashed before the seq).
func stashMetaFragment(u *url.URL, key, value string) {
	values, _ := url.ParseQuery(u.Fragment)
	if values == nil {
		values = url.Values{}
	}
	values.Set(key, value)
	u.Fragment = values.Encode()
}

// decideHTTPVersion — parity с Xray (splithttp/dialer.go decideHTTPVersion,
// идентичен в 26.1.13 и 26.7.11).
//
// InHive 2026-07-19: наш порт расходился с апстримом в двух местах, оба роняли
// соединение в HTTP/1.1 там, где Xray идёт по HTTP/2:
//
//  1. Пустой ALPN. Было `len(NextProtos()) == 0 → "1.1"`; у Xray пустой список
//     не является особым случаем — под правило "1.1" попадает ТОЛЬКО список
//     ровно из одного элемента "http/1.1", всё остальное (в т.ч. пустое) → "2".
//     Конфиг без `alpn` (а такие у нас живые — напр. миграция 042) уезжал на
//     h1-путь, где POST'ы строго последовательны, а ответы на них вообще не
//     вычитываются (H1Conn.UnreadedResponsesCount нигде не инкрементится).
//  2. REALITY. У Xray это первая же проверка: reality → всегда "2", независимо
//     от ALPN. У нас ветки не было вовсе.
//
// Порядок проверок сохранён апстримный: reality → nil → len != 1 → значение.
func decideHTTPVersion(tlsConfig tls.Config) string {
	if tlsConfig != nil && tls.IsRealityClientConfig(tlsConfig) {
		return "2"
	}
	if tlsConfig == nil {
		return "1.1"
	}
	if len(tlsConfig.NextProtos()) != 1 {
		return "2"
	}
	if tlsConfig.NextProtos()[0] == "http/1.1" {
		return "1.1"
	}
	if tlsConfig.NextProtos()[0] == "h3" {
		return "3"
	}
	return "2"
}

func getBaseRequestURL(options *option.V2RayXHTTPBaseOptions, dest M.Socksaddr, tlsConfig tls.Config) (url.URL, error) {
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = options.Host
	if requestURL.Host == "" && tlsConfig != nil {
		requestURL.Host = tlsConfig.ServerName()
	}
	if requestURL.Host == "" {
		requestURL.Host = dest.AddrString()
	}
	requestURL.Path = options.Path
	if err := sHTTP.URLSetPath(&requestURL, options.Path); err != nil {
		return requestURL, E.New(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	requestURL.Path = options.GetNormalizedPath()
	requestURL.RawQuery = options.GetNormalizedQuery()
	return requestURL, nil
}

func createHTTPClient(dest M.Socksaddr, dialer N.Dialer, options *option.V2RayXHTTPBaseOptions, tlsConfig tls.Config) DialerClient {
	httpVersion := decideHTTPVersion(tlsConfig)
	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := dialer.DialContext(ctxInner, "tcp", dest)
		if err != nil {
			return nil, err
		}
		if httpVersion != "3" && tlsConfig != nil {
			return tls.ClientHandshake(ctxInner, conn, tlsConfig)
		}
		return conn, nil
	}
	var keepAlivePeriod time.Duration
	if options.Xmux != nil {
		keepAlivePeriod = time.Duration(options.Xmux.HKeepAlivePeriod) * time.Second
	}
	var transport http.RoundTripper
	switch httpVersion {
	case "3":
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.QuicgoH3KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		quicConfig := &quic.Config{
			MaxIdleTimeout: net.ConnIdleTimeout,
			// these two are defaults of quic-go/http3. the default of quic-go (no
			// http3) is different, so it is hardcoded here for clarity.
			// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
			MaxIncomingStreams: -1,
			KeepAlivePeriod:    keepAlivePeriod,
		}
		transport = &http3.Transport{
			QUICConfig: quicConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udpConn, dErr := dialer.DialContext(ctx, N.NetworkUDP, dest)
				if dErr != nil {
					return nil, dErr
				}
				return qtls.DialEarly(ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), tlsConfig, cfg)
			},
		}
	case "2":
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.ChromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		transport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	default:
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}
		transport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: net.ConnIdleTimeout,
			// chunked transfer download with KeepAlives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
	}
	client := &DefaultDialerClient{
		options: options,
		client: &http.Client{
			Transport: transport,
		},
		httpVersion:    httpVersion,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}
	return client
}
