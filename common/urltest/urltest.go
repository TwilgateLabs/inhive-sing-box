package urltest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

var _ adapter.URLTestHistoryStorage = (*HistoryStorage)(nil)

type HistoryStorage struct {
	access       sync.RWMutex
	delayHistory map[string]*adapter.URLTestHistory
	updateHook   *observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory: make(map[string]*adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) SetHook(hook *observable.Subscriber[struct{}]) {
	s.updateHook = hook
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.delayHistory[tag]
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.StoreURLTestHistory(tag, &adapter.URLTestHistory{
		Delay: 65535,
		Time:  time.Now(),
	})
	// s.access.Lock()
	// // delete(s.delayHistory, tag)
	// s.access.Unlock()
	// s.notifyUpdated()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) *adapter.URLTestHistory {
	s.access.Lock()
	if old, ok := s.delayHistory[tag]; ok && history != nil {
		old.Delay = history.Delay
		old.Time = history.Time
		if history.IpInfo != nil {
			old.IpInfo = history.IpInfo
		}
	} else {
		s.delayHistory[tag] = history
	}
	history = s.delayHistory[tag]
	s.access.Unlock()
	s.notifyUpdated()
	return history
}

func (s *HistoryStorage) AddOnlyIpToHistory(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	if old, ok := s.delayHistory[tag]; ok && history != nil {
		old.IpInfo = history.IpInfo
	} else {
		s.delayHistory[tag] = history
	}
	s.access.Unlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) notifyUpdated() {
	updateHook := s.updateHook
	if updateHook != nil {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHook = nil
	return nil
}

func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if detour == nil {
		err = fmt.Errorf("urltest dialer is nil")
		return
	}
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	start := time.Now()
	// InHive fresh-probe (2026-07-22): пулящиеся протоколы (sing-mux; xhttp
	// xmux h2/h3; hysteria2/tuic QUIC-сессия) ПЕРЕИСПОЛЬЗУЮТ живое транспортное
	// соединение в обычном DialContext. После смены оператора/сети
	// протухший-но-ещё-живой пул отвечает на пробу → ЛОЖНЫЙ зелёный, хотя новое
	// соединение сейчас не встаёт. Когда клиент помечает пробу fresh (clash
	// delay-хендлер: query `fresh=1`; шлёт InHive Dart-клиент для НЕ-несущих
	// резидентных серверов), дайлим свежим транспортом МИМО пула через opt-in
	// adapter.ProbeFreshDialer — боевой пул при этом НЕ трогаем (транзиентная
	// сессия закрывается вместе с probe-conn). Протоколы без пула интерфейс не
	// реализуют → обычный DialContext, для них и так свежий (no-op). БЕЗ
	// fresh-флага — поведение бит-в-бит апстримное.
	var instance net.Conn
	if isProbeFresh(ctx) {
		if fresh, ok := detour.(adapter.ProbeFreshDialer); ok {
			instance, err = fresh.DialProbeFresh(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
		} else {
			instance, err = detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
		}
	} else {
		instance, err = detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	}
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
	}
	req, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: C.TCPTimeout,
	}
	defer client.CloseIdleConnections()
	select {
	case <-ctx.Done():
		return
	default:
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	resp.Body.Close()

	t = uint16(time.Since(start) / time.Millisecond)

	if IsUnifiedDelayFromContext(ctx) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		second := time.Now()
		resp, err = client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
		t = uint16(time.Since(second) / time.Millisecond) //to avid timeout in the second call
	}
	return
}
