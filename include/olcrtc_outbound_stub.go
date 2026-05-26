//go:build !with_olcrtc

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// registerOLCRTCOutbound — stub когда build БЕЗ tag with_olcrtc. Config с outbound
// type "olcrtc" приводит к explicit error при load — без silent fallback.
//
// Включение: rebuild с -tags "...with_olcrtc..." + go get github.com/openlibrecommunity/olcrtc.
func registerOLCRTCOutbound(registry *outbound.Registry) {
	outbound.Register[option.OLCRTCOutboundOptions](
		registry,
		C.TypeOLCRTC,
		func(
			ctx context.Context,
			router adapter.Router,
			logger log.ContextLogger,
			tag string,
			options option.OLCRTCOutboundOptions,
		) (adapter.Outbound, error) {
			return nil, E.New(`olcrtc outbound is not included in this build, rebuild with -tags with_olcrtc`)
		},
	)
}
