package uuid

// Порт Xray common/uuid, урезанный до реально используемого (fatal-audit
// 2026-08-25): xhttp-клиенту (transport/v2rayxhttp/client.go) нужны только
// New() + String() для генерации xmux session id. Выпилены мёртвые
// ParseString (паниковал slice-out-of-range на неканонических дефисах,
// PoC: "-11111111-2222-3333-4444-5555555"), ParseBytes (E.New с []byte —
// паника format.ToString в error-path) и Equals. Понадобится парсинг —
// портировать из эталона Xray (см. upstream.toml, запись xhttp) С фиксом
// границ, не восстанавливать из git как есть.

import (
	"crypto/rand"
	"encoding/hex"

	common "github.com/sagernet/sing-box/common/xray"
)

var byteGroups = []int{8, 4, 4, 4, 12}

type UUID [16]byte

// String returns the string representation of this UUID.
func (u *UUID) String() string {
	bytes := u.Bytes()
	result := hex.EncodeToString(bytes[0 : byteGroups[0]/2])
	start := byteGroups[0] / 2
	for i := 1; i < len(byteGroups); i++ {
		nBytes := byteGroups[i] / 2
		result += "-"
		result += hex.EncodeToString(bytes[start : start+nBytes])
		start += nBytes
	}
	return result
}

// Bytes returns the bytes representation of this UUID.
func (u *UUID) Bytes() []byte {
	return u[:]
}

// New creates a UUID with random value.
func New() UUID {
	var uuid UUID
	common.Must2(rand.Read(uuid.Bytes()))
	uuid[6] = (uuid[6] & 0x0f) | (4 << 4)
	uuid[8] = (uuid[8]&(0xff>>2) | (0x02 << 6))
	return uuid
}
