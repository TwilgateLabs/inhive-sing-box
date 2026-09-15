package crypto

import (
	"crypto/rand"
	"math/big"
)

// RandBetween returns a random int64 in [from, to).
// Xray v26.9.9 reordered the guards: normalize the range first, then short-circuit
// both the empty (d == 0) and the single-value (d == 1) ranges without touching
// crypto/rand. Result is identical to the old form, one RNG call cheaper.
func RandBetween(from int64, to int64) int64 {
	if from > to {
		from, to = to, from
	}
	if d := to - from; d == 0 || d == 1 {
		return from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}
