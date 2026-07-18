package v2rayhttpupgrade

import (
	std_bufio "bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	dialer              N.Dialer
	serverAddr          M.Socksaddr
	requestURL          url.URL
	headers             http.Header
	host                string
	maxEarlyData        uint32
	earlyDataHeaderName string
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayHTTPUpgradeOptions, tlsConfig tls.Config) (*Client, error) {
	if tlsConfig != nil {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{"http/1.1"})
		}
		dialer = tls.NewDialer(dialer, tlsConfig)
	}
	var host string
	if options.Host != "" {
		host = options.Host
	} else if tlsConfig != nil && tlsConfig.ServerName() != "" {
		host = tlsConfig.ServerName()
	} else {
		host = serverAddr.String()
	}
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = serverAddr.String()
	requestURL.Path = options.Path
	err := sHTTP.URLSetPath(&requestURL, options.Path)
	if err != nil {
		return nil, E.Cause(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	headers := make(http.Header)
	for key, value := range options.Headers {
		headers[key] = value
	}
	if headers.Get("User-Agent") == "" { //H
		headers.Set("User-Agent", C.DefaultBrowserAgent) //H
	} //H
	return &Client{
		dialer:              dialer,
		serverAddr:          serverAddr,
		requestURL:          requestURL,
		headers:             headers,
		host:                host,
		maxEarlyData:        options.MaxEarlyData,
		earlyDataHeaderName: options.EarlyDataHeaderName,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	// InHive: when no early data is configured (the default), connect eagerly
	// exactly as before — byte-identical behavior.
	if c.maxEarlyData <= 0 {
		return c.dialContext(ctx, &c.requestURL, c.headers)
	}
	// Early-data path: defer the upgrade GET until the first Write so the early
	// bytes can be folded into the request (path or header), mirroring the
	// WebSocket EarlyWebsocketConn flow.
	return &EarlyHTTPUpgradeConn{Client: c, ctx: ctx, create: make(chan struct{})}, nil
}

// dialContext performs the HTTP Upgrade handshake against requestURL with the
// given headers and returns the upgraded raw connection.
func (c *Client) dialContext(ctx context.Context, requestURL *url.URL, headers http.Header) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	// InHive: bound the upgrade handshake with a deadline (mirrors the ws client,
	// v2raywebsocket/client.go:83-96). Without it, request.Write / http.ReadResponse
	// have no deadline and don't observe ctx — a server that accepts the TCP/TLS
	// connection then goes silent (host blackhole, our play2go recidive) hangs the
	// dial FOREVER, leaking the caller's route dialSem slot (invisible to the
	// circuit-breaker, which never sees a returned dial) and wedging the whole
	// tunnel once the global cap fills. Also close conn on every handshake-error
	// path so a dead server can't leak an fd per attempt.
	var deadlineConn net.Conn
	if deadline.NeedAdditionalReadDeadline(conn) {
		deadlineConn = deadline.NewConn(conn)
	} else {
		deadlineConn = conn
	}
	deadlineConn.SetDeadline(time.Now().Add(C.TCPTimeout))
	request := &http.Request{
		Method: http.MethodGet,
		URL:    requestURL,
		Header: headers.Clone(),
		Host:   c.host,
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	err = request.Write(deadlineConn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	bufReader := std_bufio.NewReader(deadlineConn)
	response, err := http.ReadResponse(bufReader, request)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if response.StatusCode != 101 ||
		!strings.EqualFold(response.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
		conn.Close()
		return nil, E.New("v2ray-http-upgrade: unexpected status: ", response.Status)
	}
	// Clear the handshake deadline before handing the conn to the caller for streaming.
	deadlineConn.SetDeadline(time.Time{})
	if bufReader.Buffered() > 0 {
		buffer := buf.NewSize(bufReader.Buffered())
		_, err = buffer.ReadFullFrom(bufReader, buffer.Len())
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = bufio.NewCachedConn(conn, buffer)
	}
	return conn, nil
}

func (c *Client) Close() error {
	return nil
}

// EarlyHTTPUpgradeConn defers the HTTP Upgrade handshake until the first Write,
// then folds up to maxEarlyData bytes into the upgrade request (base64-RawURL
// into the path, or into earlyDataHeaderName when set), mirroring
// v2raywebsocket.EarlyWebsocketConn.
type EarlyHTTPUpgradeConn struct {
	*Client
	ctx    context.Context
	conn   atomic.Pointer[net.Conn]
	access sync.Mutex
	create chan struct{}
	err    error
}

func (c *EarlyHTTPUpgradeConn) loadConn() net.Conn {
	p := c.conn.Load()
	if p == nil {
		return nil
	}
	return *p
}

func (c *EarlyHTTPUpgradeConn) writeRequest(content []byte) error {
	var (
		earlyData []byte
		lateData  []byte
		conn      net.Conn
		err       error
	)
	if len(content) > int(c.maxEarlyData) {
		earlyData = content[:c.maxEarlyData]
		lateData = content[c.maxEarlyData:]
	} else {
		earlyData = content
	}
	if len(earlyData) > 0 {
		earlyDataString := base64.RawURLEncoding.EncodeToString(earlyData)
		if c.earlyDataHeaderName == "" {
			requestURL := c.requestURL
			requestURL.Path += earlyDataString
			conn, err = c.dialContext(c.ctx, &requestURL, c.headers)
		} else {
			headers := c.headers.Clone()
			headers.Set(c.earlyDataHeaderName, earlyDataString)
			conn, err = c.dialContext(c.ctx, &c.requestURL, headers)
		}
	} else {
		conn, err = c.dialContext(c.ctx, &c.requestURL, c.headers)
	}
	if err != nil {
		return err
	}
	if len(lateData) > 0 {
		if _, err = conn.Write(lateData); err != nil {
			return err
		}
	}
	c.conn.Store(&conn)
	return nil
}

func (c *EarlyHTTPUpgradeConn) Read(b []byte) (int, error) {
	conn := c.loadConn()
	if conn == nil {
		<-c.create
		if c.err != nil {
			return 0, c.err
		}
		conn = c.loadConn()
	}
	return conn.Read(b)
}

func (c *EarlyHTTPUpgradeConn) Write(b []byte) (int, error) {
	if conn := c.loadConn(); conn != nil {
		return conn.Write(b)
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	if conn := c.loadConn(); conn != nil {
		return conn.Write(b)
	}
	err := c.writeRequest(b)
	c.err = err
	close(c.create)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *EarlyHTTPUpgradeConn) Close() error {
	if conn := c.loadConn(); conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *EarlyHTTPUpgradeConn) LocalAddr() net.Addr {
	if conn := c.loadConn(); conn != nil {
		return conn.LocalAddr()
	}
	return M.Socksaddr{}
}

func (c *EarlyHTTPUpgradeConn) RemoteAddr() net.Addr {
	if conn := c.loadConn(); conn != nil {
		return conn.RemoteAddr()
	}
	return M.Socksaddr{}
}

func (c *EarlyHTTPUpgradeConn) SetDeadline(t time.Time) error {
	if conn := c.loadConn(); conn != nil {
		return conn.SetDeadline(t)
	}
	return nil
}

func (c *EarlyHTTPUpgradeConn) SetReadDeadline(t time.Time) error {
	if conn := c.loadConn(); conn != nil {
		return conn.SetReadDeadline(t)
	}
	return nil
}

func (c *EarlyHTTPUpgradeConn) SetWriteDeadline(t time.Time) error {
	if conn := c.loadConn(); conn != nil {
		return conn.SetWriteDeadline(t)
	}
	return nil
}

func (c *EarlyHTTPUpgradeConn) Upstream() any {
	return c.loadConn()
}

func (c *EarlyHTTPUpgradeConn) LazyHeadroom() bool {
	return c.loadConn() == nil
}
