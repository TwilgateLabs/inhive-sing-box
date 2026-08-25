package invalid

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Endpoint — endpoint-двойник invalid-Outbound'а. У endpoint'ов (wireguard/awg)
// не было аналога hinvalid-fallback'а: ошибка создания уезжала в box.New и
// клала ВЕСЬ профиль (adapter/endpoint/manager.go возвращал её как есть, у
// box.go endpoint-цикл фатален). Теперь один битый wg:// стоит одного мёртвого
// сервера с читаемой причиной в DisplayType, как у аутбаундов.
var _ adapter.Endpoint = (*Endpoint)(nil)

type Endpoint struct {
	Outbound
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, invalidOptions option.InvalidOptions) (adapter.Endpoint, error) {
	out, err := New(ctx, router, logger, tag, invalidOptions)
	if err != nil {
		return nil, err
	}
	return &Endpoint{Outbound: *out.(*Outbound)}, nil
}

func (h *Endpoint) Start(stage adapter.StartStage) error {
	return nil
}

func (h *Endpoint) Close() error {
	return nil
}
