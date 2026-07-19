package option

import (
	"strconv"
	"strings"
	"testing"

	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"

	"golang.org/x/net/http2/hpack"
)

// serverIsPaddingValid — ДОСЛОВНАЯ копия серверной проверки Xray
// (transport/internet/splithttp/xpadding.go, Config.IsPaddingValid). Тест намеренно
// валидирует наш генератор ТОЙ ЖЕ функцией, которой его судит сервер: расхождение
// между «как мы генерируем» и «как он проверяет» уже стоило нам 2.5% отказов 400 на
// каждом запросе (см. комментарий у generateXPadding).
func serverIsPaddingValid(paddingValue string, from, to int32, method string) bool {
	if paddingValue == "" {
		return false
	}
	switch method {
	case xhttpPaddingTokenish:
		const tolerance = int32(xhttpPaddingValidationTolerance)
		n := int32(hpack.HuffmanEncodeLength(paddingValue))
		f := from - tolerance
		t := to + tolerance
		if f < 0 {
			f = 0
		}
		return n >= f && n <= t
	default: // repeat-x
		n := int32(len(paddingValue))
		return n >= from && n <= to
	}
}

// Регрессия 2026-07-19: tokenish-padding обязан проходить серверную проверку на ВСЕЙ
// ширине диапазона длин, а не только на верхней его части.
//
// Старый генератор отдавал N случайных base62-символов, чья Huffman-длина ≈ 0.8·N,
// поэтому при N < 126 сервер видел < 98 и отвечал 400. Длина берётся случайно на
// каждый запрос, так что баг проявлялся как ~2.5% случайных отказов — и убивал
// upload-сессию целиком (upload_queue собирает строго по порядку).
func TestXPaddingTokenishPassesServerValidation(t *testing.T) {
	// Дефолтный диапазон — тот, что действует для конфига без xPaddingBytes
	// (именно такой у живого CDN-бэкенда id=59).
	const from, to = int32(100), int32(1000)
	for length := int(from); length <= int(to); length++ {
		v := generateXPadding(xhttpPaddingTokenish, length)
		if !serverIsPaddingValid(v, from, to, xhttpPaddingTokenish) {
			t.Fatalf("tokenish padding length=%d rejected by server validation: huffman=%d, want within [%d,%d]",
				length, hpack.HuffmanEncodeLength(v), from-2, to+2)
		}
	}
}

// Каждая сгенерированная строка должна попадать в допуск ОТНОСИТЕЛЬНО ЗАПРОШЕННОЙ
// длины, а не просто в широкий диапазон — иначе тест выше проходил бы и на
// генераторе, который всегда возвращает одну и ту же среднюю длину.
func TestXPaddingTokenishHitsRequestedHuffmanLength(t *testing.T) {
	for _, length := range []int{100, 126, 200, 500, 1000} {
		for i := 0; i < 50; i++ {
			v := generateXPadding(xhttpPaddingTokenish, length)
			got := int(hpack.HuffmanEncodeLength(v))
			if diff := got - length; diff > xhttpPaddingValidationTolerance || diff < -xhttpPaddingValidationTolerance {
				t.Fatalf("tokenish(%d): huffman length = %d, want %d±%d", length, got, length, xhttpPaddingValidationTolerance)
			}
		}
	}
}

// repeat-x сервер меряет обычной len() — здесь длина обязана совпадать точно.
func TestXPaddingRepeatXExactLength(t *testing.T) {
	for _, length := range []int{1, 100, 1000} {
		v := generateXPadding(xhttpPaddingRepeatX, length)
		if len(v) != length || strings.Trim(v, "X") != "" {
			t.Fatalf("repeat-x(%d) = %q (len %d), want %d copies of 'X'", length, v, len(v), length)
		}
		if !serverIsPaddingValid(v, int32(length), int32(length), xhttpPaddingRepeatX) {
			t.Fatalf("repeat-x(%d) rejected by server validation", length)
		}
	}
}

// Генератор обязан покрывать весь алфавит без перекоса. Наивный `% 62` по случайному
// байту делал первые 8 символов заметно вероятнее (256 % 62 = 8) — статистический
// признак ровно в том поле, которое существует ради маскировки.
func TestXPaddingTokenishCharsetUnbiased(t *testing.T) {
	counts := map[rune]int{}
	total := 0
	for i := 0; i < 300; i++ {
		for _, r := range generateXPadding(xhttpPaddingTokenish, 500) {
			counts[r]++
			total++
		}
	}
	if len(counts) < 60 {
		t.Fatalf("charset coverage = %d distinct chars, want ~62", len(counts))
	}
	expected := float64(total) / 62.0
	for _, r := range xhttpBase62 {
		got := float64(counts[r])
		// 'X'/'Z' законно встречаются чаще — ими идёт подгонка длины.
		if r == 'X' || r == 'Z' {
			continue
		}
		if got < expected*0.7 || got > expected*1.3 {
			t.Errorf("char %q appeared %.0f times, expected ~%.0f (±30%%) — biased sampling", r, got, expected)
		}
	}
}

// Диапазон по умолчанию должен совпадать с апстримным (100..1000): именно он
// действует для конфигов без xPaddingBytes и задаёт границы серверной проверки.
func TestXPaddingDefaultRangeMatchesUpstream(t *testing.T) {
	var o V2RayXHTTPBaseOptions
	r := o.GetNormalizedXPaddingBytes()
	if r.From != 100 || r.To != 1000 {
		t.Fatalf("default xPaddingBytes = %d..%d, want 100..1000", r.From, r.To)
	}
	o.XPaddingBytes = &Xbadoption.Range{From: 7, To: 9}
	if r2 := o.GetNormalizedXPaddingBytes(); r2.From != 7 || r2.To != 9 {
		t.Fatalf("explicit xPaddingBytes = %d..%d, want 7..9", r2.From, r2.To)
	}
}

// Регрессия 2026-07-19: xhttp-запрос обязан нести СОГЛАСОВАННЫЙ браузерный отпечаток.
//
// Раньше уходил ровно один заголовок (User-Agent Chrome 144) без единого заголовка,
// который настоящий Chrome шлёт всегда — ни Client Hints, ни Sec-Fetch-*, ни Accept.
// Для bot/abuse-слоя CDN это не маскировка, а маркер подделки. Отдельно проверяем
// Cache-Control/Pragma: без них эдж вправе считать длинный streaming-GET download-половины
// кэшируемым объектом и применять к нему свои лимиты.
func TestXHTTPRequestHeadersCarryCoherentBrowserFingerprint(t *testing.T) {
	var o V2RayXHTTPBaseOptions
	h := o.GetRequestHeader("https://cdn.example.com/api-test/abc")

	// Client Hints пишутся прямым присваиванием в map (парити с апстримом: так на
	// HTTP/1.1 сохраняется ровно то написание, которое шлёт Chrome — "Sec-CH-UA", а
	// не канонизированное "Sec-Ch-Ua"). Поэтому и читать их надо по сырому ключу:
	// http.Header.Get канонизирует и такие заголовки «не видит».
	get := func(k string) string {
		if v := h[k]; len(v) > 0 {
			return v[0]
		}
		return h.Get(k)
	}
	for _, k := range []string{
		"User-Agent", "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform",
		"Accept", "Accept-Language", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
		"Sec-Fetch-Site", "Cache-Control", "Pragma",
	} {
		if get(k) == "" {
			t.Errorf("missing %s — Chrome UA without it is a self-evident forgery to a CDN bot layer", k)
		}
	}
	if h.Get("Cache-Control") != "no-cache" || h.Get("Pragma") != "no-cache" {
		t.Errorf("Cache-Control/Pragma = %q/%q, want no-cache/no-cache", h.Get("Cache-Control"), h.Get("Pragma"))
	}
	// UA и Sec-CH-UA обязаны заявлять ОДНУ И ТУ ЖЕ мажорную версию — рассогласование
	// между ними само по себе является отпечатком.
	if !strings.Contains(h.Get("User-Agent"), strconv.Itoa(xhttpChromeMajorVersion)) {
		t.Errorf("User-Agent %q does not carry major version %d", h.Get("User-Agent"), xhttpChromeMajorVersion)
	}
	if !strings.Contains(get("Sec-CH-UA"), `"Google Chrome";v="`+strconv.Itoa(xhttpChromeMajorVersion)+`"`) {
		t.Errorf("Sec-CH-UA %q inconsistent with UA major version %d", get("Sec-CH-UA"), xhttpChromeMajorVersion)
	}
}

// Пользовательский User-Agent из config.headers — это явная воля автора конфига,
// маскировку поверх него не навязываем (апстримная семантика).
func TestXHTTPCustomUserAgentIsLeftAlone(t *testing.T) {
	o := V2RayXHTTPBaseOptions{Headers: map[string]string{"User-Agent": "MyCustomAgent/1.0"}}
	h := o.GetRequestHeader("https://cdn.example.com/x")
	if h.Get("User-Agent") != "MyCustomAgent/1.0" {
		t.Fatalf("custom UA overwritten: %q", h.Get("User-Agent"))
	}
	if h.Get("Sec-CH-UA") != "" {
		t.Errorf("custom UA must not gain Chrome client hints, got %q", h.Get("Sec-CH-UA"))
	}
}
