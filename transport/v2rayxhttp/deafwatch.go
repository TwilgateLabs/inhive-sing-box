package xhttp

// InHive 2026-07-31: детектор «глухого download» для packet-up — НАБЛЮДАТЕЛЬ,
// ничего не рвёт и не переоткрывает.
//
// Класс бага (device-verified, unreportable): CDN-эдж режет idle download-GET
// пробкет-up сессии (~60с без байтов вниз), при этом:
//   - h2-соединение до эджа ЖИВО (эдж отвечает на PING'ы → health-check
//     ReadIdleTimeout 45с + pingTimeout 15с НЕ спасает — ему не на что
//     срабатывать);
//   - uplink-POST'ы продолжают получать 200 (upload-половина работает);
//   - приложение ждёт ответы через мёртвый download вечно;
//   - в логах — ТИШИНА: ни одна сторона не считает себя сломанной.
// См. XTLS/Xray-core#6554. Это ровно тот случай, когда отказ невидим и обязан
// стать наблюдаемым (feedback_meta_unreportable_bug_class): лог + счётчик,
// БЕЗ teardown/reopen (сервер-сайд фикс — отдельно, Никита: «наблюдаемость
// сейчас, сервер потом»).
//
// Сигналы (оба per-session):
//   - lastDownlinkNano — реальные байты из download-half (n>0 в Read
//     обёртки deafReader поверх conn.reader = WaitReadCloser/resp.Body).
//     h2 PING'и и заголовки сюда НЕ попадают — только payload, поэтому
//     keepalive не маскирует глухоту.
//   - lastUploadProgressNano — forward-progress аплинка: PostPacket вернул
//     nil (для h2/h3 это буквально «сервер ответил 200 на POST», см.
//     dialer.go PostPacket). НЕ «вызвали Write»: зависший POST прогрессом
//     не считается.
//
// Условие срабатывания:
//
//	(now-lastDownlink) > deafSilenceThreshold  И  (now-lastUploadProgress) < deafUplinkActiveWindow
//
// Гейт по uplink-активности защищает ЗАКОННО-idle сессии (long-poll, idle
// SSH, push-соединения): там молчат ОБЕ половины → uplink-условие ложно →
// не логируем. Глухота = асимметрия «вниз мёртво, вверх живо».
//
// Порог 52с — обоснование:
//   - МЕНЬШЕ CDN idle-cut (~60с, XTLS#6554): лог обязан лечь ДО обрыва,
//     пока сессия ещё в состоянии «висит-но-жива» — после обрыва GET умрёт
//     и картину замусорят обычные stream-error'ы. С тиком 5с лог ложится
//     на 52–57с тишины.
//   - БОЛЬШЕ любого легитимного downlink-затишья при АКТИВНОМ аплоаде:
//     пока POST'ы получают 200, проксируемый TCP непрерывно порождает
//     ACK'и вниз; десятки секунд НУЛЯ байтов вниз при живом аплинке —
//     аномалия по построению.
//
// Окно uplink-активности 15с: при любом реальном аплоаде каденс POST'ов —
// доли секунды (scMinPostsIntervalMs дефолт ~30мс), 15с прощает короткие
// паузы источника, но отсекает по-настоящему idle сессии (там POST'ов нет
// минутами).
//
// Один лог на эпизод: episodeLogged взводится CAS'ом при срабатывании,
// сбрасывается при возобновлении downlink — следующая тишина логируется
// снова, спама «каждый тик» нет.
//
// Watchdog — тикер per-session (паттерн retired-sweep из zombie-фикса:
// не зависит от трафика, в отличие от проверки в read-цикле, которому в
// глухом состоянии как раз НЕЧЕГО читать). Горутина умирает с сессией по
// uploadCtx (отменяется в conn.onClose и на ошибочных путях DialContext).

import (
	"context"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// Пороги — var, не const, чтобы тесты могли ужать времена (тот же приём, что
// xmuxHandoutCloseGrace в mux.go). Обоснование значений — в шапке файла.
var (
	deafSilenceThreshold   = 52 * time.Second
	deafUplinkActiveWindow = 15 * time.Second
	deafWatchTick          = 5 * time.Second
)

type deafWatch struct {
	logger  logger.ContextLogger // nil-safe: тесты могут не давать логгер
	session string               // короткий id сессии для лога

	lastDownlinkNano       atomic.Int64 // unix nano последнего РЕАЛЬНОГО байта вниз
	lastUploadProgressNano atomic.Int64 // unix nano последнего 200-на-POST; 0 = никогда
	episodeLogged          atomic.Bool  // «эта тишина уже залогирована»
}

// newDeafWatch стартует отсчёт тишины с МОМЕНТА СОЗДАНИЯ сессии: сессия,
// которая с рождения активно шлёт, но так и не получила НИ БАЙТА вниз —
// это и есть баг-сценарий, он обязан сработать.
func newDeafWatch(l logger.ContextLogger, session string) *deafWatch {
	w := &deafWatch{logger: l, session: session}
	w.lastDownlinkNano.Store(time.Now().UnixNano())
	return w
}

// noteDownlink — реальные байты пришли вниз: двигаем метку и закрываем эпизод
// (следующая тишина будет залогирована заново). Методы nil-safe: для
// не-packet-up режимов детектор не создаётся (w == nil), вызовы — no-op.
func (w *deafWatch) noteDownlink() {
	if w == nil {
		return
	}
	w.lastDownlinkNano.Store(time.Now().UnixNano())
	w.episodeLogged.Store(false)
}

// noteUploadProgress — PostPacket вернул nil (сервер принял POST, 200).
func (w *deafWatch) noteUploadProgress() {
	if w == nil {
		return
	}
	w.lastUploadProgressNano.Store(time.Now().UnixNano())
}

// run — watchdog-тикер; живёт до отмены ctx (= uploadCtx сессии).
func (w *deafWatch) run(ctx context.Context) {
	ticker := time.NewTicker(deafWatchTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			w.check(ctx, now)
		}
	}
}

// check — одна проверка условия; возвращает true, если ИМЕННО этот вызов
// залогировал эпизод (для тестов). Порядок проверок: сперва дешёвый гейт по
// uplink-активности (он же защита законных idle-сессий), потом тишина, потом
// CAS однократности.
func (w *deafWatch) check(ctx context.Context, now time.Time) bool {
	nowNano := now.UnixNano()
	lastUp := w.lastUploadProgressNano.Load()
	if lastUp == 0 || nowNano-lastUp > int64(deafUplinkActiveWindow) {
		return false // uplink не активен → законно-idle сессия, молчим
	}
	silence := nowNano - w.lastDownlinkNano.Load()
	if silence <= int64(deafSilenceThreshold) {
		return false // download живой (или тишина ещё короткая)
	}
	if !w.episodeLogged.CompareAndSwap(false, true) {
		return false // этот эпизод уже залогирован
	}
	recordSilentDownload() // счётчик для telemetry-строки (chunkhist.go)
	if w.logger != nil {
		silenceSec := strconv.FormatInt(silence/int64(time.Second), 10)
		uploadSec := strconv.FormatInt((nowNano-lastUp)/int64(time.Second), 10)
		w.logger.WarnContext(ctx,
			"[xhttp] download глух "+silenceSec+
				"с при активном uplink (session="+w.session+
				", last_downlink="+silenceSec+
				"с назад, last_upload_200="+uploadSec+
				"с назад) — вероятно CDN idle-cut, см. XTLS#6554")
	}
	return true
}

// deafReader — обёртка download-half (conn.reader): каждый Read с n>0 двигает
// lastDownlink. Считаются только РЕАЛЬНО доставленные приложению байты —
// ровно то, чего в глухом состоянии нет.
type deafReader struct {
	io.ReadCloser
	watch *deafWatch
}

func (r *deafReader) Read(b []byte) (int, error) {
	n, err := r.ReadCloser.Read(b)
	if n > 0 {
		r.watch.noteDownlink()
	}
	return n, err
}
