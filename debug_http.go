// debug_http.go — pprof и debug HTTP server. По умолчанию ВЫКЛЮЧЕНО.
// Чтобы включить для локальной диагностики CPU/goroutine leaks —
// выставь env var INHIVE_PPROF=1 перед запуском приложения.
//
// Доступ только с localhost (127.0.0.1:9091). Наружу не выставляется.
// В production deployment переменная не ставится → сервер не поднимается.
package box

import (
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // регистрирует /debug/pprof/* handlers
	"os"
	"sync"

	"github.com/sagernet/sing-box/option"
)

var (
	debugHTTPServer interface{ Close() error }
	debugHTTPOnce   sync.Once
)

// init поднимает pprof при загрузке пакета, если env var выставлена.
// Это гарантирует запуск pprof даже если в sing-box конфиге нет debug секции.
func init() {
	if os.Getenv("INHIVE_PPROF") != "1" {
		return
	}
	debugHTTPOnce.Do(startPprofServer)
}

// applyDebugListenOption — вызывается из конфига, оставлен для совместимости.
func applyDebugListenOption(_ option.DebugOptions) {
	if os.Getenv("INHIVE_PPROF") != "1" {
		return
	}
	debugHTTPOnce.Do(startPprofServer)
}

func startPprofServer() {
	const addr = "127.0.0.1:9091"
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[inhive-pprof] failed to listen on %s: %v", addr, err)
		return
	}
	server := &http.Server{Handler: http.DefaultServeMux}
	debugHTTPServer = server
	log.Printf("[inhive-pprof] listening on http://%s/debug/pprof/", addr)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[inhive-pprof] server error: %v", err)
		}
	}()
}
