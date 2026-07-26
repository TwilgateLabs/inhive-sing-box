package v2rayhttp

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	xnet "github.com/sagernet/sing-box/common/xray/net"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	transport  http.RoundTripper
	http2      bool
	requestURL url.URL
	host       []string
	method     string
	headers    http.Header
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	var transport http.RoundTripper
	if tlsConfig == nil {
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		}
	} else {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		tlsDialer := tls.NewDialer(dialer, tlsConfig)
		// InHive 2026-07-26: health-check по умолчанию, а не только когда
		// idle_timeout задан в подписке (в диком виде он не задан почти никогда).
		// Без него мёртвый после сна девайса H2-коннект (NAT снёс TCP, RST не
		// пришёл) жил в пуле вечно, и все новые стримы уходили в чёрную дыру до
		// TCP RTO — «первые N секунд после пробуждения VPN не работает».
		// Дефолт = ChromeH2KeepAlivePeriod (45s), та же константа, что у нашего
		// порта Xray splithttp (v2rayxhttp/client.go) — browser-подобный PING-
		// период, не выделяющийся для DPI. Явный idle_timeout из подписки
		// по-прежнему уважается.
		//
		// Отрицательный idle_timeout = «выключить пинги совсем» — конвенция
		// Xray, дословно повторённая в нашем порту splithttp
		// (v2rayxhttp/client.go: keepAlivePeriod<0 → 0). Без неё у чужой
		// подписки не остаётся способа отказаться от нашего дефолта, а это
		// wire-поведение на ЧУЖОМ сервере: универсальный клиент обязан давать
		// владельцу конфига последнее слово (feedback_domain_universal_client).
		readIdleTimeout := time.Duration(options.IdleTimeout)
		switch {
		case readIdleTimeout == 0:
			readIdleTimeout = xnet.ChromeH2KeepAlivePeriod
		case readIdleTimeout < 0:
			readIdleTimeout = 0
		}
		transport = &http2.Transport{
			ReadIdleTimeout: readIdleTimeout,
			PingTimeout:     time.Duration(options.PingTimeout),
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.STDConfig) (net.Conn, error) {
				return tlsDialer.DialTLSContext(ctx, M.ParseSocksaddr(addr))
			},
		}
	}
	if options.Method == "" {
		options.Method = http.MethodPut
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
	headers := options.Headers.Build()

	if host := headers.Get("Host"); host != "" { //H
		headers.Del("Host")    //H
		requestURL.Host = host //H
	}
	if headers.Get("User-Agent") == "" { //H
		headers.Set("User-Agent", C.DefaultBrowserAgent) //H
	} //H
	return &Client{
		ctx:        ctx,
		dialer:     dialer,
		serverAddr: serverAddr,
		requestURL: requestURL,
		host:       options.Host,
		method:     options.Method,
		headers:    headers, //H
		transport:  transport,
		http2:      tlsConfig != nil,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	if !c.http2 {
		return c.dialHTTP(ctx)
	} else {
		return c.dialHTTP2(ctx)
	}
}

func (c *Client) dialHTTP(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	if err != nil {
		return nil, err
	}

	request := &http.Request{
		Method: c.method,
		URL:    &c.requestURL,
		Header: c.headers.Clone(),
	}
	switch hostLen := len(c.host); hostLen {
	case 0:
		request.Host = c.serverAddr.AddrString()
	case 1:
		request.Host = c.host[0]
	default:
		request.Host = c.host[rand.Intn(hostLen)]
	}

	return NewHTTP1Conn(conn, request), nil
}

func (c *Client) dialHTTP2(ctx context.Context) (net.Conn, error) {
	pipeInReader, pipeInWriter := io.Pipe()
	request := &http.Request{
		Method: c.method,
		Body:   pipeInReader,
		URL:    &c.requestURL,
		Header: c.headers.Clone(),
	}
	request = request.WithContext(ctx)
	switch hostLen := len(c.host); hostLen {
	case 0:
		// https://github.com/v2fly/v2ray-core/blob/master/transport/internet/http/config.go#L13
		request.Host = "www.example.com"
	case 1:
		request.Host = c.host[0]
	default:
		request.Host = c.host[rand.Intn(hostLen)]
	}
	conn := NewLateHTTPConn(pipeInWriter)
	go func() {
		response, err := c.transport.RoundTrip(request)
		if err != nil {
			conn.Setup(nil, err)
		} else if response.StatusCode != 200 {
			response.Body.Close()
			conn.Setup(nil, E.New("v2ray-http: unexpected status: ", response.Status))
		} else {
			conn.Setup(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) Close() error {
	c.transport = ResetTransport(c.transport)
	return nil
}
