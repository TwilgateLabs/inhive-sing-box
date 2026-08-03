//go:build with_utls

package tls

import "testing"

// TestUTLSFingerprintXrayParity фиксирует инвариант «универсального клиента»:
// имя отпечатка, которое принимает Xray, обязано приниматься и нами.
//
// Цена нарушения конкретная: `uTLSClientHelloID` возвращает ошибку, ошибка
// роняет разбор ВСЕГО outbound'а, и сервер из чужой подписки просто исчезает у
// пользователя — при том что отпечаток влияет лишь на маскировку ClientHello и
// ни на что в протоколе. Список сверен с Xray v26.7.11
// (`transport/internet/tls/tls.go`: PresetFingerprints + ModernFingerprints +
// OtherFingerprints); при бампе Xray-эталона в upstream.toml — пересверить.
func TestUTLSFingerprintXrayParity(t *testing.T) {
	t.Parallel()
	// Пресеты Xray (короткие имена из GUI-клиентов) + версионные написания.
	names := []string{
		"", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
		"random", "randomized", "randomizednoalpn",

		"hellogolang", "hellorandomized", "hellorandomizedalpn", "hellorandomizednoalpn",
		"hellochrome_auto", "hellochrome_58", "hellochrome_62", "hellochrome_70",
		"hellochrome_72", "hellochrome_83", "hellochrome_87", "hellochrome_96",
		"hellochrome_100", "hellochrome_102", "hellochrome_106_shuffle",
		"hellochrome_120", "hellochrome_131", "hellochrome_133",
		"hellofirefox_auto", "hellofirefox_55", "hellofirefox_56", "hellofirefox_63",
		"hellofirefox_65", "hellofirefox_99", "hellofirefox_102", "hellofirefox_105",
		"hellofirefox_120", "hellofirefox_148",
		"helloedge_auto", "helloedge_85", "helloedge_106",
		"hellosafari_auto", "hellosafari_16_0", "hellosafari_26_3",
		"helloios_auto", "helloios_11_1", "helloios_12_1", "helloios_13", "helloios_14",
		"hello360_auto", "hello360_7_5", "hello360_11_0",
		"helloqq_auto", "helloqq_11_1",
		"helloandroid_11_okhttp",
	}
	for _, name := range names {
		id, err := uTLSClientHelloID(name)
		if err != nil {
			t.Errorf("fingerprint %q: Xray принимает, мы отвергаем: %v", name, err)
			continue
		}
		if id.Client == "" {
			t.Errorf("fingerprint %q: разрешился в пустой ClientHelloID", name)
		}
	}

	// Регистр не должен решать судьбу сервера: провайдеры пишут и `Chrome`, и
	// `HelloChrome_120`.
	for _, name := range []string{"Chrome", "HelloChrome_120", "RandomizedNoALPN"} {
		if _, err := uTLSClientHelloID(name); err != nil {
			t.Errorf("fingerprint %q: регистр не должен влиять: %v", name, err)
		}
	}

	// Заведомо несуществующее имя обязано оставаться ошибкой — тихая подмена
	// увела бы отпечаток в сторону от заявленного в конфиге.
	if _, err := uTLSClientHelloID("definitely_not_a_browser"); err == nil {
		t.Error("неизвестный отпечаток должен возвращать ошибку, а не подменяться молча")
	}
}
