//go:build race

package xhttp

// raceEnabled сообщает, собран ли пакет с -race. Под гонко-детектором
// sync.Pool.Put намеренно дропает элемент с вероятностью 1/4 (runtime,
// sync/pool.go), из-за чего тесты, завязанные на детерминированное
// переиспользование/дренаж uploadRawPool, флейкают не по нашей вине.
const raceEnabled = true
