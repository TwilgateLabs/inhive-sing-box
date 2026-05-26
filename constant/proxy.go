package constant

const (
	TypeTun          = "tun"
	TypeRedirect     = "redirect"
	TypeTProxy       = "tproxy"
	TypeDirect       = "direct"
	TypeBlock        = "block"
	TypeDNS          = "dns"
	TypeSOCKS        = "socks"
	TypeHTTP         = "http"
	TypeMixed        = "mixed"
	TypeShadowsocks  = "shadowsocks"
	TypeVMess        = "vmess"
	TypeTrojan       = "trojan"
	TypeNaive        = "naive"
	TypeWireGuard    = "wireguard"
	TypeWARP         = "warp"
	TypeHysteria     = "hysteria"
	TypeTor          = "tor"
	TypeSSH          = "ssh"
	TypeShadowTLS    = "shadowtls"
	TypeMieru        = "mieru"
	TypeDnstt        = "dnstt"
	TypeAnyTLS       = "anytls"
	TypeShadowsocksR = "shadowsocksr"
	TypeVLESS        = "vless"
	TypeTUIC         = "tuic"
	TypeHysteria2    = "hysteria2"
	TypePsiphon      = "psiphon"
	TypeTunnelClient = "tunnel_client"
	TypeTunnelServer = "tunnel_server"
	TypeTailscale    = "tailscale"
	TypeDERP         = "derp"
	TypeResolved     = "resolved"
	TypeSSMAPI       = "ssm-api"
	TypeCCM          = "ccm"
	TypeOCM          = "ocm"
	TypeOOMKiller    = "oom-killer"

	// value остаётся "hinvalid" для backward compat с существующими конфигами.
	// InHive builder ставит этот тип при невалидном config entry — wire format stable.
	TypeInvalidConfig = "hinvalid"
	// TypeXray removed 2026-04-20 (dehiddification): был stub "not implemented yet";
	// xray-compatible URL schemes (xvless://, xvmess://, xtrojan://) теперь парсятся
	// через native sing-box VLESS/VMess/Trojan parsers (sing-box 1.12+ имеет TLS Fragment,
	// XTLS Vision, uTLS fingerprint — всё что нужно).
	TypeCustom   = "custom"   //H
	TypeAwg      = "awg"      //H
	TypeBalancer = "balancer" //H
	// TypeDNSTT removed 2026-04-19 (dehiddification). Re-add with clean net2share/vaydns upstream when реально понадобится.
	TypeUTProto = "utproto" //H
	// TypeOLCRTC: stealth tunnel через легальные WebRTC SFU (jitsi/wbstream/telemost) —
	// emergency fallback для РФ LTE whitelist'ов. См. project_olcrtc_scope.md.
	TypeOLCRTC = "olcrtc" //H
)

const (
	TypeSelector = "selector"
	TypeURLTest  = "urltest"
)

func ProxyDisplayName(proxyType string) string {
	switch proxyType {
	case TypeTun:
		return "TUN"
	case TypeRedirect:
		return "Redirect"
	case TypeTProxy:
		return "TProxy"
	case TypeDirect:
		return "Direct"
	case TypeBlock:
		return "Block"
	case TypeDNS:
		return "DNS"
	case TypeSOCKS:
		return "SOCKS"
	case TypeHTTP:
		return "HTTP"
	case TypeMixed:
		return "Mixed"
	case TypeShadowsocks:
		return "Shadowsocks"
	case TypeVMess:
		return "VMess"
	case TypeTrojan:
		return "Trojan"
	case TypeNaive:
		return "Naive"
	case TypeWireGuard:
		return "WireGuard"
	case TypeWARP:
		return "WARP"
	case TypeHysteria:
		return "Hysteria"
	case TypeTor:
		return "Tor"
	case TypeSSH:
		return "SSH"
	case TypeShadowTLS:
		return "ShadowTLS"
	case TypeShadowsocksR:
		return "ShadowsocksR"
	case TypeVLESS:
		return "VLESS"
	case TypeTUIC:
		return "TUIC"
	case TypeHysteria2:
		return "Hysteria2"
	case TypeMieru:
		return "Mieru"
	case TypeDnstt:
		return "DNSTT"
	case TypeAnyTLS:
		return "AnyTLS"
	case TypePsiphon:
		return "Psiphon"
	case TypeTailscale:
		return "Tailscale"
	case TypeSelector:
		return "Selector"
	case TypeURLTest:
		return "URLTest"
	case TypeInvalidConfig:
		return "Invalid"
	case TypeCustom:
		return "custom"
	case TypeTunnelClient:
		return "Tunnel Client"
	case TypeTunnelServer:
		return "Tunnel Server"
	case TypeAwg:
		return "Awg"
	case TypeBalancer:
		return "Balancer"
	case TypeUTProto:
		return "UTProto"
	case TypeOLCRTC:
		return "OLCRTC"
	default:
		return "Unknown"
	}
}

const DefaultBrowserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
