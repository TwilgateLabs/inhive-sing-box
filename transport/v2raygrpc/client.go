package v2raygrpc

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	ctx         context.Context
	dialer      N.Dialer
	serverAddr  string
	serviceName string
	dialOptions []grpc.DialOption
	conn        atomic.Pointer[grpc.ClientConn]
	connAccess  sync.Mutex
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayGRPCOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	var dialOptions []grpc.DialOption
	if tlsConfig != nil {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(NewTLSTransportCredentials(tlsConfig)))
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if options.IdleTimeout > 0 {
		dialOptions = append(dialOptions, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Duration(options.IdleTimeout),
			Timeout:             time.Duration(options.PingTimeout),
			PermitWithoutStream: options.PermitWithoutStream,
		}))
	}
	dialOptions = append(dialOptions, grpc.WithConnectParams(grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  500 * time.Millisecond,
			Multiplier: 1.5,
			Jitter:     0.2,
			MaxDelay:   19 * time.Second,
		},
		MinConnectTimeout: 5 * time.Second,
	}))
	dialOptions = append(dialOptions, grpc.WithContextDialer(func(ctx context.Context, server string) (net.Conn, error) {
		return dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(server))
	}))
	// InHive: opt-in CDN-fronting knobs. Both default to empty → no dial option
	// appended, so the gRPC :authority/User-Agent stay at grpc-go defaults
	// (byte-identical to the original behavior).
	if options.Authority != "" {
		dialOptions = append(dialOptions, grpc.WithAuthority(options.Authority))
	}
	if options.UserAgent != "" {
		// NOTE: grpc-go appends its own "grpc-go/<ver>" suffix to the UA. Xray
		// instead injects via reflection for an exact fingerprint; for our
		// CDN-fronting use the WithUserAgent prefix is what backends route on,
		// so this is the pragmatic, dependency-free choice.
		dialOptions = append(dialOptions, grpc.WithUserAgent(options.UserAgent))
	}
	//nolint:staticcheck
	dialOptions = append(dialOptions, grpc.WithReturnConnectionError())
	return &Client{
		ctx:         ctx,
		dialer:      dialer,
		serverAddr:  serverAddr.String(),
		serviceName: options.ServiceName,
		dialOptions: dialOptions,
	}, nil
}

func (c *Client) connect() (*grpc.ClientConn, error) {
	conn := c.conn.Load()
	if conn != nil && conn.GetState() != connectivity.Shutdown {
		return conn, nil
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	conn = c.conn.Load()
	if conn != nil && conn.GetState() != connectivity.Shutdown {
		return conn, nil
	}
	// InHive: bound the blocking dial. WithReturnConnectionError (NewClient) implies
	// WithBlock → grpc.DialContext blocks until the conn is Ready. Passing the
	// box-lifetime c.ctx (no deadline) means a blackholed server hangs this dial
	// FOREVER — holding connAccess and leaking the caller's route dialSem slot,
	// invisible to the circuit-breaker (health updates only AFTER DialContext
	// returns, and this one never does → 256 zombies wedge the whole tunnel). The
	// bounded ctx makes a dead server fail fast, freeing the slot and letting the
	// breaker trip. It bounds only connection SETUP; the established ClientConn
	// outlives dialCtx (grpc keeps what it needs), so long-lived streams are unaffected.
	dialCtx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer cancel()
	//nolint:staticcheck
	conn, err := grpc.DialContext(dialCtx, c.serverAddr, c.dialOptions...)
	if err != nil {
		return nil, err
	}
	c.conn.Store(conn)
	return conn, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	clientConn, err := c.connect()
	if err != nil {
		return nil, err
	}
	client := NewGunServiceClient(clientConn).(GunServiceCustomNameClient)
	ctx, cancel := common.ContextWithCancelCause(ctx)
	// grpc.WaitForReady(false) — fail-fast: на не-Ready conn (например refused →
	// TransientFailure) открытие стрима падает сразу с Unavailable, а не виснет
	// в ожидании backoff-реконнекта. ctx НЕ оборачиваем таймаутом: он живёт со
	// стримом, а дедлайн убил бы долгоживущий стрим; fail-fast решает задачу
	// "не зависнуть на открытии" корректно.
	stream, err := client.TunCustomName(ctx, c.serviceName, grpc.WaitForReady(false))
	if err != nil {
		cancel(err)
		// Мягкая инвалидация ТОЛЬКО post-failure: если conn реально мёртв
		// (Shutdown/TransientFailure), закрываем его и снимаем из кэша через
		// CAS, чтобы следующий connect() передёрнул свежий. Превентивно НЕ
		// трогаем — у здорового conn grpc-go сам реконнектится с backoff, и
		// dial-storm устраивать нельзя. CAS гарантирует, что мы не закроем
		// чужой свежий conn, подставленный параллельным connect().
		c.invalidateConn(clientConn)
		return nil, err
	}
	return NewGRPCConn(stream, cancel), nil
}

// invalidateConn закрывает залипший ClientConn и снимает его из кэша, но
// только если он действительно в терминальном/сбойном состоянии. Вызывается
// исключительно после фактического провала открытия стрима.
func (c *Client) invalidateConn(conn *grpc.ClientConn) {
	state := conn.GetState()
	if state != connectivity.Shutdown && state != connectivity.TransientFailure {
		return
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	// CAS: закрываем и обнуляем только если в кэше всё ещё ровно этот conn.
	if c.conn.CompareAndSwap(conn, nil) {
		conn.Close()
	}
}

func (c *Client) Close() error {
	conn := c.conn.Swap(nil)
	if conn != nil {
		conn.Close()
	}
	return nil
}
