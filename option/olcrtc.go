package option

// OLCRTCOutboundOptions конфигурирует stealth tunnel через легальные WebRTC SFU
// (jitsi / wbstream / telemost). Реализация — github.com/openlibrecommunity/olcrtc
// pinned commit, см. project_olcrtc_scope.md.
//
// Принципиально: olcrtc — emergency fallback для РФ LTE whitelist'ов когда
// классические outbound'ы (Reality/Naive/UTProto/AWG) сломаны network-level
// блокировкой foreign IPs. Не основной транспорт.
//
// Build tag: `with_olcrtc` (см. include/olcrtc_outbound_stub.go).
type OLCRTCOutboundOptions struct {
	DialerOptions

	// AuthProvider выбирает named auth provider зарегистрированный в olcrtc:
	//   - "jitsi"    — XMPP/Jingle через meet1.arbitr.ru / meet.cryptopro.ru (primary, гос-инфра)
	//   - "wbstream" — LiveKit-based stream.wb.ru (backup #1)
	//   - "telemost" — Yandex SFU (backup #2)
	// Пустое значение — direct engine mode (нужны Engine/URL/Token).
	AuthProvider string `json:"auth_provider,omitempty"`

	// RoomID — room URL или ID для AuthProvider. Для jitsi это full URL вида
	// "https://meet1.arbitr.ru/inhive-shared-001".
	RoomID string `json:"room_id"`

	// Engine — direct engine mode (без auth provider). Значения: "livekit", "goolom", "jitsi".
	// Используется только когда AuthProvider пуст. Default = "livekit".
	Engine string `json:"engine,omitempty"`

	// URL / Token — direct mode credentials. URL это WS endpoint SFU, Token это
	// pre-issued credential. Используется только когда AuthProvider пуст.
	URL   string `json:"url,omitempty"`
	Token string `json:"token,omitempty"`

	// Name — display name при join'е в room. Случайно сгенерированный если пусто.
	Name string `json:"name,omitempty"`

	// DNSServer — кастомный DNS resolver для auth API calls (например "8.8.8.8:53").
	// По умолчанию использует system resolver.
	DNSServer string `json:"dns_server,omitempty"`

	// ProxyAddr / ProxyPort — опциональный SOCKS5 proxy для outbound auth/signaling
	// traffic. Не используется для media plane (WebRTC).
	ProxyAddr string `json:"proxy_addr,omitempty"`
	ProxyPort int    `json:"proxy_port,omitempty"`
}
