package tls

import (
	"crypto/rand"
	"strings"
	"unicode"
)

// randomizeCase returns s with each letter rune randomly upper- or lower-cased.
// Non-letter runes (digits, dots, dashes) are passed through unchanged — saving
// the unicode table lookup that produces no effect on them.
//
// Uses crypto/rand so consecutive calls cannot be replayed by a DPI rule that
// memorized a previous fingerprint. One Read of 32 bytes (256 random bits)
// covers up to 256 letter positions before re-seeding — fewer syscalls than
// per-rune Intn.
//
// Returns input unchanged when empty.
//
// Note: per RFC 6066, hostname in TLS SNI is case-insensitive (matches DNS
// canonicalization). The receiving server treats `ExAmPlE.cOm` identically
// to `example.com`. DPI rules written as case-sensitive byte matchers
// (`bytes.Contains(sni, "youtube")`) miss the randomized form — legitimate
// per-spec evasion of common middleboxes.
func randomizeCase(s string) string {
	if s == "" {
		return s
	}

	var rb [32]byte
	var rIdx int
	var bit uint

	var b strings.Builder
	b.Grow(len(s))

	for _, c := range s {
		if !unicode.IsLetter(c) {
			b.WriteRune(c)
			continue
		}
		if rIdx == 0 && bit == 0 {
			// fill 256 random bits — covers up to 256 letter positions
			_, _ = rand.Read(rb[:])
		}
		if rb[rIdx]&(1<<bit) == 0 {
			b.WriteRune(unicode.ToLower(c))
		} else {
			b.WriteRune(unicode.ToUpper(c))
		}
		bit++
		if bit == 8 {
			bit = 0
			rIdx++
			if rIdx == len(rb) {
				rIdx = 0 // wraps; next iter triggers re-fill via top condition
			}
		}
	}
	return b.String()
}
