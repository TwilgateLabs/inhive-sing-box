package v2rayhttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// freezableProxy — TCP-прокси до httptest-сервера, который по флагу перестаёт
// пересылать байты (имитация мёртвого пути: NAT-мэппинг умер после сна,
// пакеты уходят в никуда). Соединение при этом не рвётся — ровно та ситуация,
// в которой TCP-стек молчит, а h2 PING обязан дать ответ «мёртв».
type freezableProxy struct {
	ln     net.Listener
	target string
	frozen atomic.Bool
}

func newFreezableProxy(t *testing.T, target string) *freezableProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezableProxy{ln: ln, target: target}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(conn)
		}
	}()
	return p
}

func (p *freezableProxy) serve(client net.Conn) {
	upstream, err := net.Dial("tcp", p.target)
	if err != nil {
		client.Close()
		return
	}
	pump := func(dst, src net.Conn) {
		defer dst.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				for p.frozen.Load() {
					time.Sleep(10 * time.Millisecond)
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pump(upstream, client)
	pump(client, upstream)
}

// TestProbeTransport: живое соединение переживает пробу, «глухое» (путь
// заморожен) — закрывается, и только оно. Свойство, ради которого проба
// заменила ResetTransport на wake-пути: не рвать то, что отвечает.
func TestProbeTransport(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	proxy := newFreezableProxy(t, server.Listener.Addr().String())
	defer proxy.ln.Close()

	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.Dial("tcp", proxy.ln.Addr().String(), cfg)
		},
	}
	client := &http.Client{Transport: transport}
	doRequest := func() error {
		resp, err := client.Get(server.URL)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}
	if err := doRequest(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if probed, closed := ProbeTransport(ctx, transport, 2*time.Second); probed != 1 || closed != 0 {
		t.Fatalf("healthy: probed=%d closed=%d, want 1/0", probed, closed)
	}

	proxy.frozen.Store(true)
	if probed, closed := ProbeTransport(ctx, transport, 300*time.Millisecond); probed != 1 || closed != 1 {
		t.Fatalf("frozen: probed=%d closed=%d, want 1/1", probed, closed)
	}
	proxy.frozen.Store(false)

	// Закрытое соединение покидает пул (MarkDead из readLoop — асинхронно).
	deadline := time.Now().Add(2 * time.Second)
	for {
		probed, _ := ProbeTransport(ctx, transport, time.Second)
		if probed == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dead conn still in pool after close")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Транспорт остаётся рабочим: следующий запрос дозванивается заново.
	if err := doRequest(); err != nil {
		t.Fatalf("request after probe-close: %v", err)
	}
	if probed, closed := ProbeTransport(ctx, transport, 2*time.Second); probed != 1 || closed != 0 {
		t.Fatalf("after redial: probed=%d closed=%d, want 1/0", probed, closed)
	}
}
