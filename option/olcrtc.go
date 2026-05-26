package option

// OLCRTCOutboundOptions конфигурирует stealth tunnel через легальные WebRTC SFU
// (jitsi / wbstream / telemost). Реализация — TwilgateLabs/inhive-olcrtc fork
// (origin: github.com/openlibrecommunity/olcrtc), см. project_olcrtc_implementation.md.
//
// Принципиально: olcrtc — emergency fallback для РФ LTE whitelist'ов когда
// классические outbound'ы (Reality/Naive/UTProto/AWG) сломаны network-level
// блокировкой foreign IPs. Не основной транспорт.
//
// Build tag: `with_olcrtc` (см. include/olcrtc_outbound_stub.go).
//
// Hardening note: эта структура реализует SEC-2 (datachannel-only) и SEC-3
// (DoH default = Quad9) из memory/security_mitigations_olcrtc_pending.md.
// Видео transports (vp8channel/seichannel/videochannel) **жёстко запрещены** —
// они открывают аттаку через crafted media frames в shared SFU rooms.
type OLCRTCOutboundOptions struct {
	DialerOptions

	// Carrier выбирает named carrier зарегистрированный pkg/olcrtc.RegisterDefaults:
	//   - "jitsi"    — XMPP/Jingle через meet1.arbitr.ru / meet.cryptopro.ru (primary, гос-инфра)
	//   - "wbstream" — LiveKit-based stream.wb.ru (backup #1)
	//   - "telemost" — Yandex SFU (backup #2)
	// Required.
	Carrier string `json:"carrier"`

	// RoomURL — room URL или ID для carrier'а. Для jitsi это full URL вида
	// "https://meet1.arbitr.ru/inhive-shared-001"; для telemost/wbstream —
	// формат specific к auth provider'у. Required.
	RoomURL string `json:"room_url"`

	// ChannelID — device identifier (UUIDv4), forwarded в CLIENT_HELLO. Required.
	// Сервер matches вход против whitelist в AuthHook. Должен быть стабильный
	// per-device (persist across restarts). Validated as UUID format.
	ChannelID string `json:"channel_id"`

	// KeyHex — 64-char hex (32 bytes) shared secret между клиентом и нашим
	// joiner на сервере. Используется как root key для muxconn cipher (AES-GCM
	// nonce derivation). Required. Validated: exactly 64 hex chars.
	KeyHex string `json:"key_hex"`

	// Transport — внутренний WebRTC sub-protocol. Hard-pinned to "datachannel"
	// в SEC-2: видео transports (vp8channel/seichannel/videochannel) принимают
	// crafted frames из shared rooms → parser bug DoS / OOB read.
	// Default = "datachannel". Любое другое значение → error.
	Transport string `json:"transport,omitempty"`

	// DNSServer — DoH/DoT resolver для auth API calls (например "9.9.9.9:53").
	// Default = "9.9.9.9:53" (Quad9) per SEC-3 — защита от DNS poisoning на
	// telemetry beacon endpoint. Должен быть в формате "host:port".
	DNSServer string `json:"dns_server,omitempty"`

	// SocksAddr — bind address для локального SOCKS5 listener'а (внутренний
	// detour для DialContext). Default = "127.0.0.1:0" (ephemeral port —
	// избегаем конфликтов между несколькими olcrtc outbounds одновременно).
	// Listen-only на loopback — не network surface.
	SocksAddr string `json:"socks_addr,omitempty"`

	// SocksUser / SocksPass — креды на локальный SOCKS5 listener. Не auth
	// против remote, чисто defense-in-depth против malicious процессов на
	// той же машине которые могли бы попасть в loopback listener. Optional
	// (если оба пустые — no auth).
	SocksUser string `json:"socks_user,omitempty"`
	SocksPass string `json:"socks_pass,omitempty"`

	// Engine / URL / Token — direct engine mode (skip carrier auth). Используется
	// только когда Carrier == "none". Остальные carriers derive credentials
	// через свой auth provider (mostly unused in our deployment, kept for
	// future direct-engine scenarios).
	Engine string `json:"engine,omitempty"`
	URL    string `json:"url,omitempty"`
	Token  string `json:"token,omitempty"`
}
