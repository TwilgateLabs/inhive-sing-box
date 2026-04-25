// Native UTProto inbound for sing-box. Replaces the dual-daemon chain
// (Python mtprotoproxy + standalone Xray VLESS) with a single process
// that terminates FakeTLS+obf2 and feeds the plain stream into sing-box
// routing via inner VLESS framing.
//
// Auth layers:
//
//  1. UTProto per-user secret — 16-byte shared key consumed by the
//     FakeTLS HMAC. Multi-user resolution picks the matching secret
//     from the configured pool.
//  2. VLESS UUID — per-user identifier inside the obf2 stream. The
//     inbound ties UUIDs to the same user pool as secrets and rejects
//     connections whose obf2 layer identifies user A but whose inner
//     VLESS UUID identifies user B.
//
// Handshake failure (unknown secret / bad TLS shape) optionally
// triggers a fallback TCP proxy to a legitimate origin so passive DPI
// sees a complete TLS handshake instead of a closed connection.
package utproto

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	utp "github.com/sagernet/sing-box/transport/utproto"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	handshakeTimeout = 15 * time.Second
	fallbackTimeout  = 10 * time.Second
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.UTProtoInboundOptions](registry, C.TypeUTProto, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	ctx          context.Context
	router       adapter.ConnectionRouterEx
	logger       logger.ContextLogger
	listener     *listener.Listener
	users        []option.UTProtoInboundUser
	utprotoUsers []utp.ServerUser
	service      *vless.Service[int]
	fallback     *option.UTProtoFallback
}

// utpUserIndexKey is the context key that carries the utproto-layer
// user index into the VLESS service callback, so we can cross-check it
// against the VLESS-layer user index before releasing the connection.
type utpUserIndexKey struct{}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.UTProtoInboundOptions) (adapter.Inbound, error) {
	if len(options.Users) == 0 {
		return nil, E.New("utproto inbound: missing users")
	}

	utprotoUsers := make([]utp.ServerUser, len(options.Users))
	uuids := make([]string, len(options.Users))
	flows := make([]string, len(options.Users))
	for i, u := range options.Users {
		raw, err := hex.DecodeString(u.Secret)
		if err != nil {
			return nil, E.Cause(err, "utproto inbound: user ", u.Name, " bad secret (expected 32 hex chars)")
		}
		if len(raw) != 16 {
			return nil, E.New("utproto inbound: user ", u.Name, " secret must be 16 bytes, got ", len(raw))
		}
		copy(utprotoUsers[i].Secret[:], raw)
		utprotoUsers[i].Name = u.Name
		if u.VLESSUUID == "" {
			return nil, E.New("utproto inbound: user ", u.Name, " missing vless_uuid")
		}
		uuids[i] = u.VLESSUUID
		flows[i] = "" // vision/flow not supported over utproto transport
	}

	h := &Inbound{
		Adapter:      inbound.NewAdapter(C.TypeUTProto, tag),
		ctx:          ctx,
		router:       uot.NewRouter(router, logger),
		logger:       logger,
		users:        options.Users,
		utprotoUsers: utprotoUsers,
		fallback:     options.Fallback,
	}
	userIndices := make([]int, len(options.Users))
	for i := range userIndices {
		userIndices[i] = i
	}
	h.service = vless.NewService[int](logger, adapter.NewUpstreamContextHandlerEx(h.newConnectionEx, h.newPacketConnectionEx))
	h.service.UpdateUsers(userIndices, uuids, flows)
	h.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: h,
	})
	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(h.listener)
}

// NewConnectionEx runs the per-connection UTProto handshake, cross-
// verifies utproto↔VLESS identity, and hands the plain stream off to
// sing-box routing. Handshake failures optionally trigger fallback.
func (h *Inbound) NewConnectionEx(ctx context.Context, rawConn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	hsCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	conn, user, err := utp.Accept(hsCtx, rawConn, h.utprotoUsers)
	if err != nil {
		h.handleHandshakeFailure(ctx, rawConn, err, onClose)
		return
	}

	utpIdx := -1
	for i := range h.utprotoUsers {
		if &h.utprotoUsers[i] == user {
			utpIdx = i
			break
		}
	}
	if utpIdx < 0 {
		N.CloseOnHandshakeFailure(rawConn, onClose, errors.New("utproto: matched user not in pool"))
		return
	}

	ctx = context.WithValue(ctx, utpUserIndexKey{}, utpIdx)
	if err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose); err != nil {
		N.CloseOnHandshakeFailure(rawConn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

// handleHandshakeFailure dispatches on HandshakeError: if a fallback
// origin is configured we replay the consumed bytes and pipe
// bidirectionally so DPI sees a complete TLS handshake. Otherwise we
// close the connection and log at debug level — most failures are
// idle-scan noise, not real user errors.
func (h *Inbound) handleHandshakeFailure(ctx context.Context, rawConn net.Conn, err error, onClose N.CloseHandlerFunc) {
	var he *utp.HandshakeError
	if !errors.As(err, &he) {
		N.CloseOnHandshakeFailure(rawConn, onClose, err)
		return
	}
	if h.fallback == nil {
		h.logger.DebugContext(ctx, "utproto handshake failed (", he.Kind, "): ", he.Err)
		N.CloseOnHandshakeFailure(rawConn, onClose, he)
		return
	}
	addr := net.JoinHostPort(h.fallback.Server, strconv.Itoa(int(h.fallback.ServerPort)))
	upstream, dialErr := net.DialTimeout(N.NetworkTCP, addr, fallbackTimeout)
	if dialErr != nil {
		h.logger.WarnContext(ctx, "utproto fallback dial ", addr, " failed: ", dialErr)
		N.CloseOnHandshakeFailure(rawConn, onClose, he)
		return
	}
	if len(he.Buffer) > 0 {
		if _, werr := upstream.Write(he.Buffer); werr != nil {
			h.logger.WarnContext(ctx, "utproto fallback replay failed: ", werr)
			_ = upstream.Close()
			N.CloseOnHandshakeFailure(rawConn, onClose, he)
			return
		}
	}
	h.logger.DebugContext(ctx, "utproto handshake failed (", he.Kind, "); proxying to fallback ", addr)
	go pipeFallback(rawConn, upstream, onClose)
}

// pipeFallback bidirectionally copies between rawConn and upstream,
// closing both when either side errors or EOFs. It runs in its own
// goroutine so the inbound accept loop is not blocked.
func pipeFallback(rawConn, upstream net.Conn, onClose N.CloseHandlerFunc) {
	defer rawConn.Close()
	defer upstream.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	var copyErr error
	var copyMu sync.Mutex
	recordErr := func(e error) {
		if e == nil || errors.Is(e, io.EOF) {
			return
		}
		copyMu.Lock()
		if copyErr == nil {
			copyErr = e
		}
		copyMu.Unlock()
	}
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstream, rawConn)
		recordErr(err)
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(rawConn, upstream)
		recordErr(err)
	}()
	wg.Wait()
	if onClose != nil {
		onClose(copyErr)
	}
}

// newConnectionEx is the VLESS service TCP callback. ctx already
// carries the VLESS user index (from auth.ContextWithUser in service.go)
// and our own utproto user index (injected before NewConnection). We
// require both to match before routing.
func (h *Inbound) newConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	vlessIdx, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	utpIdx, _ := ctx.Value(utpUserIndexKey{}).(int)
	if vlessIdx != utpIdx {
		h.logger.WarnContext(ctx, "dual-auth mismatch: utproto user=", utpIdx, " vless user=", vlessIdx)
		N.CloseOnHandshakeFailure(conn, onClose, errors.New("utproto: dual-auth user mismatch"))
		return
	}
	userName := h.users[vlessIdx].Name
	if userName == "" {
		userName = F.ToString(vlessIdx)
	} else {
		metadata.User = userName
	}
	h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

// newPacketConnectionEx handles VLESS UDP-in-TCP (command=0x02). Same
// dual-auth check as the TCP path.
func (h *Inbound) newPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	vlessIdx, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	utpIdx, _ := ctx.Value(utpUserIndexKey{}).(int)
	if vlessIdx != utpIdx {
		h.logger.WarnContext(ctx, "dual-auth mismatch (udp): utproto user=", utpIdx, " vless user=", vlessIdx)
		N.CloseOnHandshakeFailure(conn, onClose, errors.New("utproto: dual-auth user mismatch"))
		return
	}
	userName := h.users[vlessIdx].Name
	if userName == "" {
		userName = F.ToString(vlessIdx)
	} else {
		metadata.User = userName
	}
	h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// M is unused but referenced indirectly by types in the file; kept to
// satisfy future UDP packetaddr work without re-importing.
var _ = M.Socksaddr{}
