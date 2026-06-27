package option

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

type _RuleAction struct {
	Action              string                    `json:"action,omitempty"`
	RouteOptions        RouteActionOptions        `json:"-"`
	RouteOptionsOptions RouteOptionsActionOptions `json:"-"`
	DirectOptions       DirectActionOptions       `json:"-"`
	BypassOptions       RouteActionOptions        `json:"-"`
	RejectOptions       RejectActionOptions       `json:"-"`
	SniffOptions        RouteActionSniff          `json:"-"`
	ResolveOptions      RouteActionResolve        `json:"-"`
}

type RuleAction _RuleAction

func (r RuleAction) MarshalJSON() ([]byte, error) {
	if r.Action == "" {
		return json.Marshal(struct{}{})
	}
	var v any
	switch r.Action {
	case C.RuleActionTypeRoute:
		r.Action = ""
		v = r.RouteOptions
	case C.RuleActionTypeRouteOptions:
		v = r.RouteOptionsOptions
	case C.RuleActionTypeDirect:
		v = r.DirectOptions
	case C.RuleActionTypeBypass:
		v = r.BypassOptions
	case C.RuleActionTypeReject:
		v = r.RejectOptions
	case C.RuleActionTypeHijackDNS:
		v = nil
	case C.RuleActionTypeSniff:
		v = r.SniffOptions
	case C.RuleActionTypeResolve:
		v = r.ResolveOptions
	default:
		return nil, E.New("unknown rule action: " + r.Action)
	}
	if v == nil {
		return badjson.MarshallObjects((_RuleAction)(r))
	}
	return badjson.MarshallObjects((_RuleAction)(r), v)
}

func (r *RuleAction) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, (*_RuleAction)(r))
	if err != nil {
		return err
	}
	var v any
	switch r.Action {
	case "", C.RuleActionTypeRoute:
		r.Action = C.RuleActionTypeRoute
		v = &r.RouteOptions
	case C.RuleActionTypeRouteOptions:
		v = &r.RouteOptionsOptions
	case C.RuleActionTypeDirect:
		v = &r.DirectOptions
	case C.RuleActionTypeBypass:
		v = &r.BypassOptions
	case C.RuleActionTypeReject:
		v = &r.RejectOptions
	case C.RuleActionTypeHijackDNS:
		v = nil
	case C.RuleActionTypeSniff:
		v = &r.SniffOptions
	case C.RuleActionTypeResolve:
		v = &r.ResolveOptions
	default:
		return E.New("unknown rule action: " + r.Action)
	}
	if v == nil {
		// check unknown fields
		return json.UnmarshalDisallowUnknownFields(data, &_RuleAction{})
	}
	err = badjson.UnmarshallExcluded(data, (*_RuleAction)(r), v)
	if err != nil {
		return err
	}
	return nil
}

type _DNSRuleAction struct {
	Action              string                       `json:"action,omitempty"`
	RouteOptions        DNSRouteActionOptions        `json:"-"`
	RouteOptionsOptions DNSRouteOptionsActionOptions `json:"-"`
	RejectOptions       RejectActionOptions          `json:"-"`
	PredefinedOptions   DNSRouteActionPredefined     `json:"-"`
}

type DNSRuleAction _DNSRuleAction

func (r DNSRuleAction) MarshalJSON() ([]byte, error) {
	if r.Action == "" {
		return json.Marshal(struct{}{})
	}
	var v any
	switch r.Action {
	case C.RuleActionTypeRoute:
		r.Action = ""
		v = r.RouteOptions
	case C.RuleActionTypeRouteOptions:
		v = r.RouteOptionsOptions
	case C.RuleActionTypeReject:
		v = r.RejectOptions
	case C.RuleActionTypePredefined:
		v = r.PredefinedOptions
	default:
		return nil, E.New("unknown DNS rule action: " + r.Action)
	}
	return badjson.MarshallObjects((_DNSRuleAction)(r), v)
}

func (r *DNSRuleAction) UnmarshalJSONContext(ctx context.Context, data []byte) error {
	err := json.Unmarshal(data, (*_DNSRuleAction)(r))
	if err != nil {
		return err
	}
	var v any
	switch r.Action {
	case "", C.RuleActionTypeRoute:
		r.Action = C.RuleActionTypeRoute
		v = &r.RouteOptions
	case C.RuleActionTypeRouteOptions:
		v = &r.RouteOptionsOptions
	case C.RuleActionTypeReject:
		v = &r.RejectOptions
	case C.RuleActionTypePredefined:
		v = &r.PredefinedOptions
	default:
		return E.New("unknown DNS rule action: " + r.Action)
	}
	return badjson.UnmarshallExcludedContext(ctx, data, (*_DNSRuleAction)(r), v)
}

type RouteActionOptions struct {
	Outbound string `json:"outbound,omitempty"`
	RawRouteOptionsActionOptions
}

type RawRouteOptionsActionOptions struct {
	OverrideAddress           string `json:"override_address,omitempty"`
	OverridePort              uint16 `json:"override_port,omitempty"`
	OverrideTunnelDestination string `json:"override_tunnel_destination,omitempty"`

	NetworkStrategy *NetworkStrategy `json:"network_strategy,omitempty"`
	FallbackDelay   uint32           `json:"fallback_delay,omitempty"`

	UDPDisableDomainUnmapping bool               `json:"udp_disable_domain_unmapping,omitempty"`
	UDPConnect                bool               `json:"udp_connect,omitempty"`
	UDPTimeout                badoption.Duration `json:"udp_timeout,omitempty"`

	TLSFragment              bool               `json:"tls_fragment,omitempty"`
	TLSFragmentFallbackDelay badoption.Duration `json:"tls_fragment_fallback_delay,omitempty"`
	TLSRecordFragment        bool               `json:"tls_record_fragment,omitempty"`
	TLSDisorder              bool               `json:"tls_disorder,omitempty"`       // InHive accelerator: split ClientHello + send first segment at TTL=1
	TLSOOB                   bool               `json:"tls_oob,omitempty"`            // InHive accelerator: split ClientHello + a trailing out-of-band (MSG_OOB) byte
	TLSDisOOB                bool               `json:"tls_disoob,omitempty"`         // InHive accelerator: disorder (first segment TTL=1) + the OOB byte
	TLSSplitPosition         int                `json:"tls_split_position,omitempty"` // InHive accelerator: byedpi-style split offset (used with tls_split_anchor)
	TLSSplitAnchor           string             `json:"tls_split_anchor,omitempty"`   // "" (random per-label) | sni | sni_end | sni_mid | absolute
	TLSFake                  bool               `json:"tls_fake,omitempty"`           // InHive accelerator: fake low-TTL benign-SNI ClientHello, real via retransmit (Win only)
	QUICFake                 bool               `json:"quic_fake,omitempty"`          // InHive accelerator: inject benign-SNI fake QUIC Initials before real (userspace, all platforms incl iOS)
}

type RouteOptionsActionOptions RawRouteOptionsActionOptions

func (r *RouteOptionsActionOptions) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, (*RawRouteOptionsActionOptions)(r))
	if err != nil {
		return err
	}
	if *r == (RouteOptionsActionOptions{}) {
		return E.New("empty route option action")
	}
	if r.TLSFragment && r.TLSRecordFragment {
		return E.New("`tls_fragment` and `tls_record_fragment` are mutually exclusive")
	}
	if r.TLSDisorder && r.TLSRecordFragment {
		return E.New("`tls_disorder` and `tls_record_fragment` are mutually exclusive")
	}
	if (r.TLSOOB || r.TLSDisOOB) && r.TLSRecordFragment {
		return E.New("`tls_oob`/`tls_disoob` and `tls_record_fragment` are mutually exclusive")
	}
	if r.TLSDisorder && r.TLSOOB {
		return E.New("`tls_disorder` and `tls_oob` are mutually exclusive")
	}
	if r.TLSDisorder && r.TLSDisOOB {
		return E.New("`tls_disorder` and `tls_disoob` are mutually exclusive")
	}
	if r.TLSOOB && r.TLSDisOOB {
		return E.New("`tls_oob` and `tls_disoob` are mutually exclusive")
	}
	switch r.TLSSplitAnchor {
	case "", "sni", "sni_end", "sni_mid", "absolute":
	default:
		return E.New("invalid `tls_split_anchor` (want sni|sni_end|sni_mid|absolute): " + r.TLSSplitAnchor)
	}
	if r.TLSFake && (r.TLSDisorder || r.TLSOOB || r.TLSDisOOB || r.TLSRecordFragment) {
		return E.New("`tls_fake` is mutually exclusive with disorder/oob/disoob/record_fragment")
	}
	return nil
}

type DNSRouteActionOptions struct {
	Server       string                `json:"server,omitempty"`
	Strategy     DomainStrategy        `json:"strategy,omitempty"`
	DisableCache bool                  `json:"disable_cache,omitempty"`
	RewriteTTL   *uint32               `json:"rewrite_ttl,omitempty"`
	ClientSubnet *badoption.Prefixable `json:"client_subnet,omitempty"`

	BypassIfFailed bool `json:"bypass_if_failed,omitempty"` //آ
}

type _DNSRouteOptionsActionOptions struct {
	Strategy     DomainStrategy        `json:"strategy,omitempty"`
	DisableCache bool                  `json:"disable_cache,omitempty"`
	RewriteTTL   *uint32               `json:"rewrite_ttl,omitempty"`
	ClientSubnet *badoption.Prefixable `json:"client_subnet,omitempty"`
}

type DNSRouteOptionsActionOptions _DNSRouteOptionsActionOptions

func (r *DNSRouteOptionsActionOptions) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, (*_DNSRouteOptionsActionOptions)(r))
	if err != nil {
		return err
	}
	if *r == (DNSRouteOptionsActionOptions{}) {
		return E.New("empty DNS route option action")
	}
	return nil
}

type _DirectActionOptions DialerOptions

type DirectActionOptions _DirectActionOptions

func (d DirectActionOptions) Descriptions() []string {
	var descriptions []string
	if d.BindInterface != "" {
		descriptions = append(descriptions, "bind_interface="+d.BindInterface)
	}
	if d.Inet4BindAddress != nil {
		descriptions = append(descriptions, "inet4_bind_address="+d.Inet4BindAddress.Build(netip.IPv4Unspecified()).String())
	}
	if d.Inet6BindAddress != nil {
		descriptions = append(descriptions, "inet6_bind_address="+d.Inet6BindAddress.Build(netip.IPv6Unspecified()).String())
	}
	if d.RoutingMark != 0 {
		descriptions = append(descriptions, "routing_mark="+fmt.Sprintf("0x%x", d.RoutingMark))
	}
	if d.ReuseAddr {
		descriptions = append(descriptions, "reuse_addr")
	}
	if d.ConnectTimeout != 0 {
		descriptions = append(descriptions, "connect_timeout="+time.Duration(d.ConnectTimeout).String())
	}
	if d.TCPFastOpen {
		descriptions = append(descriptions, "tcp_fast_open")
	}
	if d.TCPMultiPath {
		descriptions = append(descriptions, "tcp_multi_path")
	}
	if d.UDPFragment != nil {
		descriptions = append(descriptions, "udp_fragment="+fmt.Sprint(*d.UDPFragment))
	}
	if d.DomainStrategy != DomainStrategy(C.DomainStrategyAsIS) {
		descriptions = append(descriptions, "domain_strategy="+d.DomainStrategy.String())
	}
	if d.FallbackDelay != 0 {
		descriptions = append(descriptions, "fallback_delay="+time.Duration(d.FallbackDelay).String())
	}
	return descriptions
}

func (d *DirectActionOptions) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, (*_DirectActionOptions)(d))
	if err != nil {
		return err
	}
	if d.Detour != "" {
		return E.New("detour is not available in the current context")
	}
	return nil
}

type _RejectActionOptions struct {
	Method string `json:"method,omitempty"`
	NoDrop bool   `json:"no_drop,omitempty"`
}

type RejectActionOptions _RejectActionOptions

func (r RejectActionOptions) MarshalJSON() ([]byte, error) {
	switch r.Method {
	case C.RuleActionRejectMethodDefault:
		r.Method = ""
	}
	return json.Marshal((_RejectActionOptions)(r))
}

func (r *RejectActionOptions) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_RejectActionOptions)(r))
	if err != nil {
		return err
	}
	switch r.Method {
	case "", C.RuleActionRejectMethodDefault:
		r.Method = C.RuleActionRejectMethodDefault
	case C.RuleActionRejectMethodDrop:
	case C.RuleActionRejectMethodReply:
	default:
		return E.New("unknown reject method: " + r.Method)
	}
	if r.Method == C.RuleActionRejectMethodDrop && r.NoDrop {
		return E.New("no_drop is not available in current context")
	}
	return nil
}

type RouteActionSniff struct {
	Sniffer badoption.Listable[string] `json:"sniffer,omitempty"`
	Timeout badoption.Duration         `json:"timeout,omitempty"`
}

type RouteActionResolve struct {
	Server       string                `json:"server,omitempty"`
	Strategy     DomainStrategy        `json:"strategy,omitempty"`
	DisableCache bool                  `json:"disable_cache,omitempty"`
	RewriteTTL   *uint32               `json:"rewrite_ttl,omitempty"`
	ClientSubnet *badoption.Prefixable `json:"client_subnet,omitempty"`
}

type DNSRouteActionPredefined struct {
	Rcode  *DNSRCode                            `json:"rcode,omitempty"`
	Answer badoption.Listable[DNSRecordOptions] `json:"answer,omitempty"`
	Ns     badoption.Listable[DNSRecordOptions] `json:"ns,omitempty"`
	Extra  badoption.Listable[DNSRecordOptions] `json:"extra,omitempty"`
}
