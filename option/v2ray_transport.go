package option

import (
	cryptorand "crypto/rand"
	"net/http"
	"net/url"
	"strings"

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
	if path[len(path)-1] != '/' {
		path = path + "/"
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

func (c *V2RayXHTTPBaseOptions) GetRequestHeader(rawURL string) http.Header {
	header := http.Header{}
	for k, v := range c.Headers {
		header.Add(k, v)
	}
	if header.Get("User-Agent") == "" {
		header.Set("User-Agent", C.DefaultBrowserAgent) //H
	}

	u, _ := url.Parse(rawURL)

	// InHive: when session/seq use header- or cookie-placement, the client.go dialer
	// stashes them in the URL fragment (xhttpMetaSeq / xhttpMetaSession) — fragments are
	// stripped from the request line by net/http, so they never leak on the wire. Apply
	// that placement here, where we hold the per-request http.Header. When unset (path/
	// query placement) the fragment is empty and nothing happens.
	if u != nil && u.Fragment != "" {
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
		if u != nil {
			u.RawQuery = "x_padding=" + strings.Repeat("X", paddingLen)
			header.Set("Referer", u.String())
		}
		return header
	}

	// obfs ON: user-controlled padding key/header/method/placement.
	c.applyXPadding(header, u, paddingLen)
	return header
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
func (c *V2RayXHTTPBaseOptions) applyXPadding(header http.Header, u *url.URL, paddingLen int) {
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
		if u != nil {
			q := u.Query()
			q.Set(key, padding)
			u.RawQuery = q.Encode()
		}
	case xhttpPlacementCookie:
		existing := header.Get("Cookie")
		cookie := key + "=" + padding
		if existing != "" {
			cookie = existing + "; " + cookie
		}
		header.Set("Cookie", cookie)
	default: // "" or "queryInHeader": embed key=padding as the query of a fake URL inside the header.
		if u != nil {
			u.RawQuery = key + "=" + padding
			header.Set(headerName, u.String())
		}
	}
}

// generateXPadding mirrors upstream: "repeat-x" (default) => N copies of 'X';
// "tokenish" => a random base62 token of N bytes (opaque, alphanumeric). Upstream's
// tokenish additionally length-tunes against the HPACK/QPACK Huffman-encoded size; we
// emit a plain base62 token of the requested length, which the server validates only by
// (loose) length range. See the implementation report for this honest simplification.
func generateXPadding(method string, length int) string {
	if length <= 0 {
		return ""
	}
	switch method {
	case xhttpPaddingTokenish:
		return randTokenish(length)
	case xhttpPaddingRepeatX, "":
		return strings.Repeat("X", length)
	default:
		return strings.Repeat("X", length)
	}
}

const xhttpBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func randTokenish(length int) string {
	buf := make([]byte, length)
	if _, err := cryptorand.Read(buf); err != nil {
		return strings.Repeat("X", length)
	}
	for i := range buf {
		buf[i] = xhttpBase62[int(buf[i])%len(xhttpBase62)]
	}
	return string(buf)
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
