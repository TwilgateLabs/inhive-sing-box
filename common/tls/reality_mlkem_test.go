package tls

import (
	"crypto/tls"
	"net"
	"testing"

	utls "github.com/metacubex/utls"
)

// Гард к ensureMLKEMFirst (InHive 2026-09-18): REALITY-сервер на Xray >= 26.9.8
// требует keyShare X25519MLKEM768 ПЕРЕД опциональным X25519, а отпечаток
// `randomized` в metacubex/utls добавляет MLKEM двумя независимыми бросками
// монетки. Тест проверяет два свойства:
//  1. БЕЗ нормализации хотя бы один seed из выборки даёт ClientHello, который
//     новый сервер отвергнет (иначе тест защищает от несуществующей проблемы);
//  2. С нормализацией ЛЮБОЙ seed и chrome дают MLKEM первым в обоих
//     расширениях, и хендшейк-стейт строится с ключами.
func buildHello(t *testing.T, id utls.ClientHelloID, viaReality bool) *utls.UConn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	cfg := &utls.Config{ServerName: "example.com", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	if viaReality {
		u, err := newRealityUConn(client, cfg, id)
		if err != nil {
			t.Fatalf("newRealityUConn(%s): %v", id.Str(), err)
		}
		return u
	}
	u := utls.UClient(client, cfg, id)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	return u
}

// mlkemFirst — то же условие, что у сервера (REALITY tls.go после 8cdf7bf9):
// MLKEM key share присутствует, и он раньше любого X25519.
func mlkemFirst(u *utls.UConn) (curvesOK, sharesOK bool) {
	for _, ext := range u.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			curvesOK = len(e.Curves) > 0 && e.Curves[0] == utls.X25519MLKEM768
		case *utls.KeyShareExtension:
			sharesOK = len(e.KeyShares) > 0 && e.KeyShares[0].Group == utls.X25519MLKEM768
		}
	}
	return
}

func randomizedWithSeed(t *testing.T, i int) utls.ClientHelloID {
	t.Helper()
	// ПРОД-веса из utls_client.go (TLS 1.3 форсирован, P256-first выключен) —
	// тест обязан проверять тот же отпечаток, что уходит с устройства.
	id := randomizedFingerprint
	seed, err := utls.NewPRNGSeed()
	if err != nil {
		t.Fatal(err)
	}
	// детерминированные, но разные seed'ы — чтобы прогон был воспроизводим
	for k := range seed {
		seed[k] = byte(i*31 + k*7)
	}
	id.Seed = seed
	return id
}

func TestRealityClientHello_MLKEMFirst(t *testing.T) {
	const seeds = 24

	// 1) лотерея реальна: голый uTLS с ПРОД-весами randomized даёт TLS 1.3 без
	//    MLKEM-first (TLS 1.2 при прод-весах невозможен — считаем для контроля).
	noKS, noMLKEM := 0, 0
	for i := 0; i < seeds; i++ {
		u := buildHello(t, randomizedWithSeed(t, i), false)
		if !uconnHasKeyShare(u) {
			noKS++
			continue
		}
		if c, s := mlkemFirst(u); !(c && s) {
			noMLKEM++
		}
	}
	if noKS != 0 {
		t.Fatalf("прод-веса обещают TLS 1.3 всегда, но %d из %d seed'ов без key_share — веса в utls_client.go разъехались", noKS, seeds)
	}
	if noMLKEM == 0 {
		t.Fatalf("голый randomized из %d seed'ов ни разу не промахнулся по MLKEM — тест ничего не охраняет, проверь utls", seeds)
	}
	t.Logf("голый randomized (прод-веса), %d seed'ов: без MLKEM-first=%d — столько отверг бы Xray >= 26.9.8", seeds, noMLKEM)

	// 2) через newRealityUConn (пересев + MLKEM-first) — все seed'ы и chrome проходят, ключи есть
	ids := []utls.ClientHelloID{utls.HelloChrome_Auto}
	for i := 0; i < seeds; i++ {
		ids = append(ids, randomizedWithSeed(t, i))
	}
	for _, id := range ids {
		u := buildHello(t, id, true)
		c, s := mlkemFirst(u)
		if !c || !s {
			t.Errorf("%s: после newRealityUConn curves=%v shares=%v", id.Str(), c, s)
		}
		kk := u.HandshakeState.State13.KeyShareKeys
		if kk == nil || (kk.Ecdhe == nil && kk.MlkemEcdhe == nil) {
			t.Errorf("%s: нет ECDHE-ключа после нормализации — REALITY не сможет вычислить authKey", id.Str())
		}
		// Провод: у MLKEM-share должны быть данные (укусило 2026-09-18 — пустой
		// share после позднего BuildHandshakeState = `error decoding message`).
		for _, ext := range u.Extensions {
			if ks, ok := ext.(*utls.KeyShareExtension); ok {
				if len(ks.KeyShares) == 0 || len(ks.KeyShares[0].Data) < 1216 { // mlkem768 encaps 1184 + x25519 32
					t.Errorf("%s: MLKEM key share без данных на проводе (len=%d)", id.Str(), len(ks.KeyShares[0].Data))
				}
			}
		}
	}
}

func uconnHasKeyShare(u *utls.UConn) bool {
	for _, ext := range u.Extensions {
		if _, ok := ext.(*utls.KeyShareExtension); ok {
			return true
		}
	}
	return false
}
