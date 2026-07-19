package option

import (
	cryptorand "crypto/rand"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"

	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

// Fragment sentinel keys: client.go stashes session/seq here for header/cookie placement.
// The URL fragment is stripped from the request line by net/http, so these never leak.
const (
	xhttpMetaSession = "__inhive_xhttp_session"
	xhttpMetaSeq     = "__inhive_xhttp_seq"
)

// XHTTPMetaSessionKey / XHTTPMetaSeqKey expose the fragment sentinel keys so the xhttp
// transport (client.go) and GetRequestHeader agree on the same fragment encoding.
func XHTTPMetaSessionKey() string { return xhttpMetaSession }
func XHTTPMetaSeqKey() string     { return xhttpMetaSeq }

type _V2RayTransportOptions struct {
	Type               string                  `json:"type"`
	HTTPOptions        V2RayHTTPOptions        `json:"-"`
	WebsocketOptions   V2RayWebsocketOptions   `json:"-"`
	QUICOptions        V2RayQUICOptions        `json:"-"`
	GRPCOptions        V2RayGRPCOptions        `json:"-"`
	HTTPUpgradeOptions V2RayHTTPUpgradeOptions `json:"-"`
	XHTTPOptions       V2RayXHTTPOptions       `json:"-"`
	// DNSTTOptions removed 2026-04-19 (dehiddification)
}

type V2RayTransportOptions _V2RayTransportOptions

func (o V2RayTransportOptions) MarshalJSON() ([]byte, error) {
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = o.HTTPUpgradeOptions
	case C.V2RayTransportTypeXHTTP:
		v = o.XHTTPOptions

	case "":
		return nil, E.New("missing transport type")
	default:
		return nil, E.New("unknown transport type: " + o.Type)
	}
	return badjson.MarshallObjects((_V2RayTransportOptions)(o), v)
}

func (o *V2RayTransportOptions) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_V2RayTransportOptions)(o))
	if err != nil {
		return err
	}
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = &o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = &o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = &o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = &o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = &o.HTTPUpgradeOptions
	case C.V2RayTransportTypeXHTTP:
		v = &o.XHTTPOptions
	default:
		return E.New("unknown transport type: " + o.Type)
	}
	err = badjson.UnmarshallExcluded(bytes, (*_V2RayTransportOptions)(o), v)
	if err != nil {
		return err
	}
	return nil
}

type V2RayHTTPOptions struct {
	Host        badoption.Listable[string] `json:"host,omitempty"`
	Path        string                     `json:"path,omitempty"`
	Method      string                     `json:"method,omitempty"`
	Headers     badoption.HTTPHeader       `json:"headers,omitempty"`
	IdleTimeout badoption.Duration         `json:"idle_timeout,omitempty"`
	PingTimeout badoption.Duration         `json:"ping_timeout,omitempty"`
}

type V2RayWebsocketOptions struct {
	Path                string               `json:"path,omitempty"`
	Headers             badoption.HTTPHeader `json:"headers,omitempty"`
	MaxEarlyData        uint32               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string               `json:"early_data_header_name,omitempty"`
	// InHive: opt-in periodic WebSocket ping keepalive (Xray-core heartbeatPeriod, seconds).
	// Zero (the default) means no ping ticker → byte-identical to the original behavior.
	HeartbeatPeriod badoption.Duration `json:"heartbeat_period,omitempty"`
}

type V2RayQUICOptions struct{}

type V2RayGRPCOptions struct {
	ServiceName         string             `json:"service_name,omitempty"`
	IdleTimeout         badoption.Duration `json:"idle_timeout,omitempty"`
	PingTimeout         badoption.Duration `json:"ping_timeout,omitempty"`
	PermitWithoutStream bool               `json:"permit_without_stream,omitempty"`
	// InHive: opt-in gRPC CDN-fronting knobs (Xray-core grpcSettings parity).
	// Authority overrides the HTTP/2 :authority pseudo-header (defaults to the
	// server address / TLS SNI when empty). UserAgent overrides the client UA.
	// Both default to empty → byte-identical to the original behavior.
	Authority string `json:"authority,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	ForceLite bool   `json:"-"` // for test
}

type V2RayHTTPUpgradeOptions struct {
	Host    string               `json:"host,omitempty"`
	Path    string               `json:"path,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
	// InHive: opt-in HTTPUpgrade early-data support (Xray-core ?ed= parity).
	// MaxEarlyData>0 enables deferring the upgrade-response read so the first
	// write pipelines with the GET (matching Xray's Ed!=0 semantics). When
	// EarlyDataHeaderName is set the early bytes are base64-RawURL placed in
	// that header; otherwise they are appended to the request path (WS-style).
	// Both default to zero/empty → byte-identical to the original behavior.
	MaxEarlyData        uint32 `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string `json:"early_data_header_name,omitempty"`
}

type V2RayXHTTPBaseOptions struct {
	Host                 string                 `json:"host,omitempty"`
	Path                 string                 `json:"path,omitempty"`
	Headers              map[string]string      `json:"headers,omitempty"`
	DomainStrategy       DomainStrategy         `json:"domainStrategy,omitempty"`
	XPaddingBytes        *Xbadoption.Range      `json:"xPaddingBytes,omitempty"`
	NoGRPCHeader         bool                   `json:"noGRPCHeader,omitempty"`
	NoSSEHeader          bool                   `json:"noSSEHeader,omitempty"`
	ScMaxEachPostBytes   *Xbadoption.Range      `json:"scMaxEachPostBytes,omitempty"`
	ScMinPostsIntervalMs *Xbadoption.Range      `json:"scMinPostsIntervalMs,omitempty"`
	ScMaxBufferedPosts   int64                  `json:"scMaxBufferedPosts,omitempty"`
	ScStreamUpServerSecs *Xbadoption.Range      `json:"scStreamUpServerSecs,omitempty"`
	Xmux                 *V2RayXHTTPXmuxOptions `json:"xmux,omitempty"`

	// --- InHive: opt-in XHTTP CDN-bypass obfuscation (upstream Xray splithttp parity).
	// All fields below default to empty/false. When unset, request generation is
	// byte-identical to the original behavior (session+seq in URL path, POST uplink,
	// x_padding=repeat-X carried inside the Referer header as queryInHeader).
	// String values match upstream constants exactly:
	//   placement: "path" | "query" | "header" | "cookie" | "queryInHeader"
	//   padding method: "repeat-x" | "tokenish"

	// UplinkHTTPMethod overrides the uplink (packet-up / stream-up / stream-one) HTTP
	// method. Empty => "POST" (current behavior). The downlink fetch is always GET.
	UplinkHTTPMethod string `json:"uplinkHTTPMethod,omitempty"`

	// SeqKey / SeqPlacement control where the per-request sequence integer is written.
	// Empty placement => "path" (appended as a /<seq> segment, current behavior).
	SeqKey       string `json:"seqKey,omitempty"`
	SeqPlacement string `json:"seqPlacement,omitempty"`

	// SessionIDKey / SessionIDPlacement control where the session UUID is written.
	// Empty placement => "path" (appended as a /<sessionId> segment, current behavior).
	// The JSON aliases sessionKey / sessionPlacement (used by some real-world configs
	// and the trigger config) are accepted too — they unmarshal into SessionKeyAlias /
	// SessionPlacementAlias and are folded into the canonical fields by
	// NormalizeXHTTPObfsAliases (called from the parser).
	SessionIDKey          string `json:"sessionIDKey,omitempty"`
	SessionIDPlacement    string `json:"sessionIDPlacement,omitempty"`
	SessionKeyAlias       string `json:"sessionKey,omitempty"`
	SessionPlacementAlias string `json:"sessionPlacement,omitempty"`

	// XPadding obfuscation knobs. XPaddingObfsMode gates the user-controlled padding
	// placement; when false the original Referer/x_padding/repeat-X path is used.
	XPaddingMethod    string `json:"xPaddingMethod,omitempty"`
	XPaddingObfsMode  bool   `json:"xPaddingObfsMode,omitempty"`
	XPaddingKey       string `json:"xPaddingKey,omitempty"`
	XPaddingHeader    string `json:"xPaddingHeader,omitempty"`
	XPaddingPlacement string `json:"xPaddingPlacement,omitempty"`
}

// XHTTP placement / padding-method constants (verbatim upstream Xray splithttp string values).
const (
	xhttpPlacementPath          = "path"
	xhttpPlacementQuery         = "query"
	xhttpPlacementHeader        = "header"
	xhttpPlacementCookie        = "cookie"
	xhttpPlacementQueryInHeader = "queryInHeader"

	xhttpPaddingRepeatX  = "repeat-x"
	xhttpPaddingTokenish = "tokenish"
)

// NormalizeXHTTPObfsAliases folds the sessionKey / sessionPlacement JSON aliases (used
// by some real-world Happ-exported configs and the trigger config) into the canonical
// SessionIDKey / SessionIDPlacement fields. The canonical keys win if both are set.
// A plain struct (rather than a custom UnmarshalJSON) is used on purpose so that
// embedding V2RayXHTTPBaseOptions in XHTTPExtra / V2RayXHTTPOptions does not hijack
// their unmarshalling (which would silently drop downloadSettings / mode).
func (c *V2RayXHTTPBaseOptions) NormalizeXHTTPObfsAliases() {
	if c.SessionIDKey == "" && c.SessionKeyAlias != "" {
		c.SessionIDKey = c.SessionKeyAlias
	}
	if c.SessionIDPlacement == "" && c.SessionPlacementAlias != "" {
		c.SessionIDPlacement = c.SessionPlacementAlias
	}
	c.SessionKeyAlias = ""
	c.SessionPlacementAlias = ""
}

type V2RayXHTTPOptions struct {
	Mode string `json:"mode,omitempty"`
	V2RayXHTTPBaseOptions
	Download *V2RayXHTTPDownloadOptions `json:"downloadSettings,omitempty"`
}

type V2RayXHTTPDownloadOptions struct {
	V2RayXHTTPBaseOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Detour string `json:"detour,omitempty"`
}

func (c *V2RayXHTTPBaseOptions) GetNormalizedPath() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	path := pathAndQuery[0]
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	// Замыкающий слэш нужен ТОЛЬКО когда в путь дописывается session и/или seq —
	// он служит разделителем сегментов (`/base/` + `<uuid>` + `/` + `<seq>`).
	//
	// InHive 2026-07-19: parity с Xray 26.7.11 (splithttp/config.go
	// GetNormalizedPath). Раньше слэш клеился БЕЗУСЛОВНО — это код Xray 26.1.13,
	// апстрим уточнил его позже. Для дефолтного placement ("path") поведение
	// побайтово прежнее, поэтому все наши текущие конфиги не затронуты. Ломалось
	// только при obfs-размещении (session/seq в header/cookie/query): туда
	// дописывать нечего, и лишний `/` менял путь запроса (`/x/` вместо `/x`) —
	// сервер матчит путь строго, получаем 404 на КАЖДЫЙ запрос без единой ошибки
	// в логе клиента.
	if c.GetNormalizedSessionPlacement() == xhttpPlacementPath ||
		c.GetNormalizedSeqPlacement() == xhttpPlacementPath {
		if path[len(path)-1] != '/' {
			path = path + "/"
		}
	}
	return path
}

func (c *V2RayXHTTPBaseOptions) GetNormalizedQuery() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	query := ""
	if len(pathAndQuery) > 1 {
		query = pathAndQuery[1]
	}
	return query
}

// GetRequestHeader строит заголовки запроса и возвращает ФАКТИЧЕСКИЙ URL, который
// надо отправить.
//
// ⚠️ InHive 2026-07-19 — ИСПРАВЛЕН SILENT-FAIL, дававший 100% отказов на конфигах
// с `xPaddingPlacement: "query"`.
//
// Функция раньше возвращала только http.Header. Для placement'ов header/cookie/
// queryInHeader этого достаточно — padding живёт в заголовке. Но для placement
// "query" padding по определению обязан попасть в СТРОКУ ЗАПРОСА, а записывался он
// в `u` — ЛОКАЛЬНУЮ КОПИЮ, распарсенную из rawURL внутри этой функции. Наружу она не
// отдавалась, вызывающий уже построил `req` из исходной строки ⇒ **padding не уходил
// на провод НИКОГДА**. Сервер (Xray splithttp) при обязательном padding отвергал
// каждый такой запрос, а у нас в логах не было ни ошибки, ни намёка: код отработал
// без err, «padding применён» — просто в объект, который выбрасывался.
//
// Это ровно тот класс, на котором мы горели весь день: err == nil, конфиг валиден,
// трафик не идёт.
//
// Поэтому сигнатура теперь отдаёт (header, effectiveURL), и вызывающий ОБЯЗАН строить
// запрос по возвращённому URL. Для всех остальных placement'ов возвращается тот же
// URL (минус fragment, который net/http всё равно не шлёт) — поведение побайтово
// прежнее.
func (c *V2RayXHTTPBaseOptions) GetRequestHeader(rawURL string) (http.Header, string) {
	header := http.Header{}
	for k, v := range c.Headers {
		header.Add(k, v)
	}
	applyMasqueradedHeaders(header)

	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		// URL не разобрался — отдаём исходную строку нетронутой. Ронять запрос здесь
		// нельзя: разбор URL не наша ответственность, его уже проверил вызывающий.
		return header, rawURL
	}

	// InHive: when session/seq use header- or cookie-placement, the client.go dialer
	// stashes them in the URL fragment (xhttpMetaSeq / xhttpMetaSession) — fragments are
	// stripped from the request line by net/http, so they never leak on the wire. Apply
	// that placement here, where we hold the per-request http.Header. When unset (path/
	// query placement) the fragment is empty and nothing happens.
	if u.Fragment != "" {
		c.applyHeaderCookieMeta(header, u.Fragment)
		u.Fragment = ""
		u.RawFragment = ""
	}

	paddingLen := int(c.GetNormalizedXPaddingBytes().Rand())
	if !c.XPaddingObfsMode {
		// Default (obfs OFF): byte-identical to the original behavior — repeat-X padding
		// carried as x_padding=... inside the Referer header (upstream "queryInHeader").
		// https://www.rfc-editor.org/rfc/rfc7541.html#appendix-B
		// h2's HPACK Header Compression feature employs a huffman encoding using a static table.
		// 'X' is assigned an 8 bit code, so HPACK compression won't change actual padding length on the wire.
		// https://www.rfc-editor.org/rfc/rfc9204.html#section-4.1.2-2
		// h3's similar QPACK feature uses the same huffman table.
		//
		// Referer несёт ФЕЙКОВЫЙ query — поэтому строим его на копии, чтобы подмена
		// RawQuery не утекла в реальный URL запроса.
		refererURL := *u
		refererURL.RawQuery = "x_padding=" + strings.Repeat("X", paddingLen)
		header.Set("Referer", refererURL.String())
		return header, u.String()
	}

	// obfs ON: user-controlled padding key/header/method/placement.
	return header, c.applyXPadding(header, u, paddingLen)
}

// applyHeaderCookieMeta places session/seq values (carried in the URL fragment as a
// url.Values-encoded string) into header- or cookie-placement. Query/path placement is
// handled in client.go directly on the URL, so this only handles the header/cookie cases.
func (c *V2RayXHTTPBaseOptions) applyHeaderCookieMeta(header http.Header, fragment string) {
	values, err := url.ParseQuery(fragment)
	if err != nil {
		return
	}
	var cookies []string
	if sid := values.Get(xhttpMetaSession); sid != "" {
		switch c.GetNormalizedSessionPlacement() {
		case xhttpPlacementHeader:
			header.Set(c.GetNormalizedSessionKey(), sid)
		case xhttpPlacementCookie:
			cookies = append(cookies, c.GetNormalizedSessionKey()+"="+sid)
		}
	}
	if seq := values.Get(xhttpMetaSeq); seq != "" {
		switch c.GetNormalizedSeqPlacement() {
		case xhttpPlacementHeader:
			header.Set(c.GetNormalizedSeqKey(), seq)
		case xhttpPlacementCookie:
			cookies = append(cookies, c.GetNormalizedSeqKey()+"="+seq)
		}
	}
	if len(cookies) > 0 {
		existing := header.Get("Cookie")
		if existing != "" {
			cookies = append([]string{existing}, cookies...)
		}
		header.Set("Cookie", strings.Join(cookies, "; "))
	}
}

// applyXPadding generates padding per XPaddingMethod and places it per XPaddingPlacement.
// Возвращает URL, который надо реально отправить: для placement "query" он ОТЛИЧАЕТСЯ
// от входного (padding дописан в строку запроса), для остальных совпадает.
func (c *V2RayXHTTPBaseOptions) applyXPadding(header http.Header, u *url.URL, paddingLen int) string {
	key := c.XPaddingKey
	if key == "" {
		key = "x_padding"
	}
	headerName := c.XPaddingHeader
	if headerName == "" {
		headerName = "Referer"
	}
	padding := generateXPadding(c.XPaddingMethod, paddingLen)

	switch c.XPaddingPlacement {
	case xhttpPlacementHeader:
		header.Set(headerName, padding)
	case xhttpPlacementQuery:
		// Единственная ветка, где padding обязан оказаться в САМОМ запросе, а не в
		// заголовке. Возвращаем изменённый URL наружу — раньше он молча терялся
		// вместе с padding'ом (см. развёрнутое обоснование над GetRequestHeader).
		q := u.Query()
		q.Set(key, padding)
		u.RawQuery = q.Encode()
		return u.String()
	case xhttpPlacementCookie:
		existing := header.Get("Cookie")
		cookie := key + "=" + padding
		if existing != "" {
			cookie = existing + "; " + cookie
		}
		header.Set("Cookie", cookie)
	default: // "" or "queryInHeader": embed key=padding as the query of a fake URL inside the header.
		// Фейковый query строим на КОПИИ: он предназначен заголовку и не должен
		// оказаться в реальном URL запроса.
		fakeURL := *u
		fakeURL.RawQuery = key + "=" + padding
		header.Set(headerName, fakeURL.String())
	}
	return u.String()
}

// generateXPadding mirrors upstream Xray (splithttp/xpadding.go GeneratePadding):
// "repeat-x" (default) => N copies of 'X'; "tokenish" => base62 token tuned so its
// HPACK/QPACK **Huffman-encoded** size is N.
//
// ⚠️ InHive 2026-07-19 — ИСПРАВЛЕН БАГ, дававший ~2.5% отказов 400 на КАЖДЫЙ запрос.
//
// Прежняя реализация отдавала N случайных base62-символов и опиралась на записанное
// здесь допущение «сервер валидирует только по (нестрогому) диапазону длины». Оно
// НЕВЕРНО. Сервер (Xray splithttp/xpadding.go IsPaddingValid, ветка tokenish) меряет
// именно Huffman-длину:
//
//	n := hpack.HuffmanEncodeLength(paddingValue)
//	valid ⟺ n ∈ [from-2, to+2]
//
// А Huffman-длина случайной base62-строки ≈ 0.8 символа (замерено: 0.7982 — ровно
// апстримная константа). При дефолтном диапазоне 100..1000 (конфиг без xPaddingBytes)
// это значит: любая случайно выбранная длина N < 126 даёт n < 98 и ОТВЕРГАЕТСЯ.
// N берётся равномерно из [100,1000] на КАЖДЫЙ запрос → 2.48% запросов получали 400.
//
// Почему это било так больно: padding уходит в каждом upload-POST, а приёмная
// сторона (upload_queue) собирает пакеты строго по порядку — один отвергнутый POST
// встаёт головой очереди и убивает сессию. При 2.5% на запрос сессия аплоада
// доживает до ~100 пакетов с вероятностью 0.975^100 ≈ 8%, то есть ~3 секунды при
// 33 POST/с. Download-стрим шлёт padding ОДИН раз при открытии GET, поэтому терял
// лишь 2.5% сессий — отсюда наблюдавшаяся асимметрия (приём 62-133 против отдачи
// 1.8-5 Мбит/с) и «стартует 300, потом падает в несколько раз».
//
// До добавления проверки resp.StatusCode != 200 (2026-07-19) эти 400 глотались
// молча и выглядели как «медленная сеть».
//
// repeat-x этим не затронут: сервер валидирует его по обычной len(), а мы отдаём
// ровно N символов 'X'.
func generateXPadding(method string, length int) string {
	if length <= 0 {
		return ""
	}
	switch method {
	case xhttpPaddingTokenish:
		if v := generateTokenishPaddingBase62(length); v != "" {
			return v
		}
		return strings.Repeat("X", length)
	case xhttpPaddingRepeatX, "":
		return strings.Repeat("X", length)
	default:
		return strings.Repeat("X", length)
	}
}

// applyMasqueradedHeaders приводит набор заголовков xhttp-запроса к СОГЛАСОВАННОМУ
// браузерному отпечатку — порт upstream Xray 26.7.11
// (common/utils/browser.go TryDefaultHeadersWith(header, "fetch") →
// applyMasqueradedHeaders, вызывается из splithttp/config.go FillStreamRequest и
// FillPacketRequest, т.е. на КАЖДОМ запросе, включая download-GET).
//
// InHive 2026-07-19. Раньше мы ставили ровно один заголовок — User-Agent Chrome 144 —
// и больше ничего. На проводе это выглядело как Chrome, у которого НЕТ ни одного
// заголовка, обязательного для Chrome: ни Client Hints (Sec-CH-UA*), ни Sec-Fetch-*,
// ни Accept/Accept-Language. Настоящий Chrome 144 шлёт их всегда, поэтому такой
// запрос — не «похожий на браузер», а наоборот: самоочевидная подделка, которую
// bot/abuse-слой CDN отличает тривиально. Референсный клиент (Happ = Xray 26.7.x)
// шлёт полный набор и на том же эдже держит поток ровно.
//
// Практически важнее прочего здесь Cache-Control/Pragma: no-cache. Download-половина
// packet-up — это ОДИН очень длинный streaming-GET. Без явного no-cache эдж вправе
// считать такой ответ кэшируемым объектом и применять к нему свои буферные/временные
// лимиты; наблюдаемая картина (эдж сам присылает RST_STREAM с INTERNAL_ERROR примерно
// через 1m0s-1m22s, «received from peer») с этим согласуется.
//
// Семантика выбора браузера — апстримная: пустой User-Agent → полный набор Chrome;
// UA-ключевое слово ("chrome"/"firefox"/"safari"/"edge"/"curl"/"golang") → набор
// соответствующего браузера; ЛЮБОЙ иной пользовательский UA из config.headers не
// трогаем вообще (пользователь знает, что делает).
//
// ⚠️ ОСОЗНАННОЕ УПРОЩЕНИЕ относительно апстрима: у Xray мажорная версия Chrome
// «дрейфует» во времени (ChromeVersion() считает её от даты + рандом), а Sec-CH-UA
// собирается под эту версию. Мы держим версию прибитой к C.DefaultBrowserAgent
// (Chrome 144) и генерируем бренды под неё же — главное, что UA и Sec-CH-UA
// СОГЛАСОВАНЫ между собой; дрейф версии — отдельная задача, требующая порта
// генератора версии целиком.
func applyMasqueradedHeaders(header http.Header) {
	switch header.Get("User-Agent") {
	case "":
		// нет UA → выдаём себя за Chrome (апстримный дефолт)
	case "chrome", "edge":
		// поддерживаем те же ключевые слова, что апстрим; набор ниже — Chromium-семейство
	case "firefox":
		header.Set("User-Agent", xhttpFirefoxUA)
		header["DNT"] = []string{"1"}
		header.Set("Accept-Language", "en-US,en;q=0.5")
		applyFetchVariantHeaders(header, "u=4")
		return
	case "safari":
		header.Set("User-Agent", xhttpSafariUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
		applyFetchVariantHeaders(header, "u=3, i")
		return
	case "golang":
		header.Del("User-Agent") // штатный net/http UA
		return
	case "curl":
		header.Set("User-Agent", xhttpCurlUA)
		return
	default:
		// пользовательский UA из config.headers — не трогаем ничего
		return
	}
	header["Sec-CH-UA"] = []string{xhttpChromeUACH}
	header["Sec-CH-UA-Mobile"] = []string{"?0"}
	header["Sec-CH-UA-Platform"] = []string{"\"Windows\""}
	header["DNT"] = []string{"1"}
	header.Set("User-Agent", C.DefaultBrowserAgent)
	header.Set("Accept-Language", "en-US,en;q=0.9")
	applyFetchVariantHeaders(header, "u=1, i")
}

// applyFetchVariantHeaders — апстримный variant "fetch" (запрос, инициированный
// скриптом через fetch/XHR, а не навигацией). Именно он подходит xhttp: это не
// переход по ссылке, а фоновый обмен данными.
func applyFetchVariantHeaders(header http.Header, priority string) {
	header.Set("Sec-Fetch-Mode", "cors")
	header.Set("Sec-Fetch-Dest", "empty")
	header.Set("Sec-Fetch-Site", "same-origin")
	if header.Get("Priority") == "" {
		header.Set("Priority", priority)
	}
	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "no-cache")
	}
	if header.Get("Pragma") == "" {
		header.Set("Pragma", "no-cache")
	}
	if header.Get("Accept") == "" {
		header.Set("Accept", "*/*")
	}
}

const (
	xhttpFirefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"
	xhttpSafariUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15"
	xhttpCurlUA    = "curl/8.7.1"
)

// xhttpChromeUACH — значение Sec-CH-UA под ту же мажорную версию, что в
// C.DefaultBrowserAgent. Формат и GREASE-таблицы взяты у апстрима
// (getGreasedChInvalidBrand / getUngreasedChUa / getGreasedChOrder): один
// «невалидный» GREASE-бренд + Chromium + Google Chrome, порядок перемешан
// детерминированно по версии-сиду.
var xhttpChromeUACH = buildChromeUACH(xhttpChromeMajorVersion)

// Держим в согласии с C.DefaultBrowserAgent (Chrome 144). Меняя UA — меняй и это.
const xhttpChromeMajorVersion = 144

func buildChromeUACH(major int) string {
	greaseNA := []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	versionNA := []string{"8", "99", "24"}
	v := strconv.Itoa(major)
	brands := []string{
		"\"Not" + greaseNA[major%len(greaseNA)] + "A" + greaseNA[(major+1)%len(greaseNA)] + "Brand\";v=\"" + versionNA[major%len(versionNA)] + "\"",
		"\"Chromium\";v=\"" + v + "\"",
		"\"Google Chrome\";v=\"" + v + "\"",
	}
	shuffle3 := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	order := shuffle3[major%len(shuffle3)]
	out := make([]string, 3)
	for i, e := range order {
		out[e] = brands[i]
	}
	return strings.Join(out, ", ")
}

const xhttpBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Huffman-кодирование даёт ~20% сжатия для base62-последовательностей.
const xhttpAvgHuffmanBytesPerCharBase62 = 0.8

// Допуск серверной проверки (upstream validationTolerance).
const xhttpPaddingValidationTolerance = 2

// generateTokenishPaddingBase62 — построчный порт upstream
// GenerateTokenishPaddingBase62: подобрать base62-строку, Huffman-длина которой
// попадает в targetHuffmanBytes ± tolerance. 'X' и 'Z' используются для подгонки,
// т.к. у них 8-битный код в статической таблице HPACK (добавление такого символа
// меняет длину на проводе ровно на 1 байт).
func generateTokenishPaddingBase62(targetHuffmanBytes int) string {
	n := int(math.Ceil(float64(targetHuffmanBytes) / xhttpAvgHuffmanBytesPerCharBase62))
	if n < 1 {
		n = 1
	}
	s, ok := randStringFromCharset(n, xhttpBase62)
	if !ok {
		return ""
	}
	const maxIter = 150
	adjustChar := byte('X')
	for iter := 0; iter < maxIter; iter++ {
		diff := int(hpack.HuffmanEncodeLength(s)) - targetHuffmanBytes
		if diff < 0 {
			diff = -diff
			if diff <= xhttpPaddingValidationTolerance {
				return s
			}
			// Слишком коротко — дописываем символ подгонки, чередуя X/Z, чтобы не
			// получить длинную серию одинаковых символов.
			s += string(adjustChar)
			if adjustChar == 'X' {
				adjustChar = 'Z'
			} else {
				adjustChar = 'X'
			}
			continue
		}
		if diff <= xhttpPaddingValidationTolerance {
			return s
		}
		// Слишком длинно — укорачиваем с конца.
		if len(s) <= 1 {
			return s
		}
		s = s[:len(s)-1]
	}
	return s
}

// randStringFromCharset — порт upstream randStringFromCharset. Использует
// rejection sampling (limit), а не `% len(charset)`: 256 % 62 = 8, поэтому наивный
// остаток делал первые 8 символов алфавита заметно вероятнее остальных — лишний
// статистический признак в том самом поле, которое существует ради маскировки.
func randStringFromCharset(n int, charset string) (string, bool) {
	if n <= 0 || len(charset) == 0 {
		return "", false
	}
	m := len(charset)
	limit := byte(256 - (256 % m))
	result := make([]byte, n)
	i := 0
	buf := make([]byte, 256)
	for i < n {
		if _, err := cryptorand.Read(buf); err != nil {
			return "", false
		}
		for _, rb := range buf {
			if rb >= limit {
				continue
			}
			result[i] = charset[int(rb)%m]
			i++
			if i == n {
				break
			}
		}
	}
	return string(result), true
}

func (c *V2RayXHTTPBaseOptions) GetNormalizedXPaddingBytes() Xbadoption.Range {
	if c.XPaddingBytes == nil || c.XPaddingBytes.To == 0 {
		return Xbadoption.Range{
			From: 100,
			To:   1000,
		}
	}
	return *c.XPaddingBytes
}

// --- InHive XHTTP obfs normalizers. Each defaults to the original behavior. ---

// GetNormalizedSeqPlacement defaults to "path" (current behavior).
func (c *V2RayXHTTPBaseOptions) GetNormalizedSeqPlacement() string {
	if c.SeqPlacement == "" {
		return xhttpPlacementPath
	}
	return c.SeqPlacement
}

// GetNormalizedSessionPlacement defaults to "path" (current behavior).
func (c *V2RayXHTTPBaseOptions) GetNormalizedSessionPlacement() string {
	if c.SessionIDPlacement == "" {
		return xhttpPlacementPath
	}
	return c.SessionIDPlacement
}

// GetNormalizedSeqKey mirrors upstream default key selection per placement.
func (c *V2RayXHTTPBaseOptions) GetNormalizedSeqKey() string {
	if c.SeqKey != "" {
		return c.SeqKey
	}
	switch c.GetNormalizedSeqPlacement() {
	case xhttpPlacementHeader:
		return "X-Seq"
	case xhttpPlacementCookie, xhttpPlacementQuery:
		return "x_seq"
	default:
		return ""
	}
}

// GetNormalizedSessionKey mirrors upstream default key selection per placement.
func (c *V2RayXHTTPBaseOptions) GetNormalizedSessionKey() string {
	if c.SessionIDKey != "" {
		return c.SessionIDKey
	}
	switch c.GetNormalizedSessionPlacement() {
	case xhttpPlacementHeader:
		return "X-Session"
	case xhttpPlacementCookie, xhttpPlacementQuery:
		return "x_session"
	default:
		return ""
	}
}

// GetNormalizedUplinkHTTPMethod defaults to "POST" (current behavior).
func (c *V2RayXHTTPBaseOptions) GetNormalizedUplinkHTTPMethod() string {
	if c.UplinkHTTPMethod == "" {
		return http.MethodPost
	}
	return c.UplinkHTTPMethod
}

func (c *V2RayXHTTPBaseOptions) GetNormalizedScMaxEachPostBytes() Xbadoption.Range {
	if c.ScMaxEachPostBytes == nil || c.ScMaxEachPostBytes.To == 0 {
		return Xbadoption.Range{
			From: 1000000,
			To:   1000000,
		}
	}
	return *c.ScMaxEachPostBytes
}

func (c *V2RayXHTTPBaseOptions) GetNormalizedScMinPostsIntervalMs() Xbadoption.Range {
	if c.ScMinPostsIntervalMs == nil || c.ScMinPostsIntervalMs.To == 0 {
		return Xbadoption.Range{
			From: 30,
			To:   30,
		}
	}
	return *c.ScMinPostsIntervalMs
}

func (c *V2RayXHTTPBaseOptions) GetNormalizedScMaxBufferedPosts() int {
	if c.ScMaxBufferedPosts == 0 {
		return 30
	}

	return int(c.ScMaxBufferedPosts)
}

func (c *V2RayXHTTPBaseOptions) GetNormalizedScStreamUpServerSecs() Xbadoption.Range {
	if c.ScStreamUpServerSecs == nil || c.ScStreamUpServerSecs.To == 0 {
		return Xbadoption.Range{
			From: 20,
			To:   80,
		}
	}
	return *c.ScStreamUpServerSecs
}

type V2RayXHTTPXmuxOptions struct {
	MaxConcurrency   Xbadoption.Range `json:"maxConcurrency"`
	MaxConnections   Xbadoption.Range `json:"maxConnections"`
	CMaxReuseTimes   Xbadoption.Range `json:"cMaxReuseTimes"`
	HMaxRequestTimes Xbadoption.Range `json:"hMaxRequestTimes"`
	HMaxReusableSecs Xbadoption.Range `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int64            `json:"hKeepAlivePeriod"`
}

func (m *V2RayXHTTPXmuxOptions) GetNormalizedMaxConcurrency() Xbadoption.Range {
	return m.MaxConcurrency
}

func (m *V2RayXHTTPXmuxOptions) GetNormalizedMaxConnections() Xbadoption.Range {
	return m.MaxConnections
}

func (m *V2RayXHTTPXmuxOptions) GetNormalizedCMaxReuseTimes() Xbadoption.Range {
	return m.CMaxReuseTimes
}

func (m *V2RayXHTTPXmuxOptions) GetNormalizedHMaxRequestTimes() Xbadoption.Range {
	return m.HMaxRequestTimes
}

func (m *V2RayXHTTPXmuxOptions) GetNormalizedHMaxReusableSecs() Xbadoption.Range {
	return m.HMaxReusableSecs
}
