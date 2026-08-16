package dns

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

var _ adapter.LegacyDNSTransport = (*TransportAdapter)(nil)

type TransportAdapter struct {
	transportType string
	transportTag  string
	dependencies  []string
	strategy      C.DomainStrategy
	clientSubnet  netip.Prefix
	// detourTag — InHive 2026-08-11: тег outbound'а, через который transport
	// реально дайлит (DialerOptions.Detour из конфига). Это ЗАЯВЛЕННАЯ в конфиге
	// связь transport→outbound, не эвристика. Нужен DNS-клиенту для fast-fail
	// запросов через outbound, помеченный down circuit-breaker'ом (инцидент
	// 2026-08-10: DNS-путь шёл мимо брейкера, ждуны стояли по 10s на имя).
	// Пусто = transport не привязан к outbound'у (default dialer) → проверка
	// брейкера не применяется.
	detourTag string
}

func NewTransportAdapter(transportType string, transportTag string, dependencies []string) TransportAdapter {
	return TransportAdapter{
		transportType: transportType,
		transportTag:  transportTag,
		dependencies:  dependencies,
	}
}

func NewTransportAdapterWithLocalOptions(transportType string, transportTag string, localOptions option.LocalDNSServerOptions) TransportAdapter {
	var dependencies []string
	if localOptions.DomainResolver != nil && localOptions.DomainResolver.Server != "" {
		dependencies = append(dependencies, localOptions.DomainResolver.Server)
	}
	return TransportAdapter{
		transportType: transportType,
		transportTag:  transportTag,
		dependencies:  dependencies,
		strategy:      C.DomainStrategy(localOptions.LegacyStrategy),
		clientSubnet:  localOptions.LegacyClientSubnet,
		detourTag:     localOptions.Detour,
	}
}

func NewTransportAdapterWithRemoteOptions(transportType string, transportTag string, remoteOptions option.RemoteDNSServerOptions) TransportAdapter {
	var dependencies []string
	if remoteOptions.DomainResolver != nil && remoteOptions.DomainResolver.Server != "" {
		dependencies = append(dependencies, remoteOptions.DomainResolver.Server)
	}
	if remoteOptions.LegacyAddressResolver != "" {
		dependencies = append(dependencies, remoteOptions.LegacyAddressResolver)
	}
	return TransportAdapter{
		transportType: transportType,
		transportTag:  transportTag,
		dependencies:  dependencies,
		strategy:      C.DomainStrategy(remoteOptions.LegacyStrategy),
		clientSubnet:  remoteOptions.LegacyClientSubnet,
		detourTag:     remoteOptions.Detour,
	}
}

func (a *TransportAdapter) Type() string {
	return a.transportType
}

func (a *TransportAdapter) Tag() string {
	return a.transportTag
}

func (a *TransportAdapter) Dependencies() []string {
	return a.dependencies
}

// DetourTag — см. комментарий у поля detourTag. Потребитель (dns.Client)
// достаёт его через анонимный interface{ DetourTag() string }, чтобы не
// расширять adapter.DNSTransport для всех сторонних реализаций.
func (a *TransportAdapter) DetourTag() string {
	return a.detourTag
}

func (a *TransportAdapter) LegacyStrategy() C.DomainStrategy {
	return a.strategy
}

func (a *TransportAdapter) LegacyClientSubnet() netip.Prefix {
	return a.clientSubnet
}
