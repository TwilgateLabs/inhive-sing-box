//go:build with_olcrtc

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/olcrtc"
)

// registerOLCRTCOutbound регистрирует "olcrtc" outbound type. Build tag with_olcrtc
// обязателен — иначе linked stub из olcrtc_outbound_stub.go возвращает ошибку.
//
// Включение: добавить `with_olcrtc` в Makefile TAGS + `go get github.com/openlibrecommunity/olcrtc@<sha>`.
func registerOLCRTCOutbound(registry *outbound.Registry) {
	olcrtc.RegisterOutbound(registry)
}
