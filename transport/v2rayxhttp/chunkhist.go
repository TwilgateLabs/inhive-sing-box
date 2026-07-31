package xhttp

import (
	"strconv"
	"strings"
	"sync/atomic"
)

// InHive instrumentation (build 129, TEMPORARY — remove once the write-scratch cap
// is finalized). Histogram of xhttp write-chunk sizes = the payload of each
// splitConn.Write, i.e. the TRUE per-chunk size fed into the h2 upload stream BEFORE
// x/net's frameScratchBufferLen cap (forked 512KB→64KB for the iOS NE jetsam fix).
// Purpose: pick the buffer size from real device data instead of a static guess —
// if chunks cluster ≤16-32KB we can drop the cap further; if they push >64KB we hold
// or raise. Read out by the mem sampler into the device diag mem.log. Lock-free
// atomics; cost per proxied Write = one switch + one atomic Add (+ a rare CAS for max).
var (
	wrChunkLE8K  atomic.Int64 // ≤ 8 KiB
	wrChunkLE16K atomic.Int64 // ≤ 16 KiB
	wrChunkLE32K atomic.Int64 // ≤ 32 KiB
	wrChunkLE64K atomic.Int64 // ≤ 64 KiB
	wrChunkGT64K atomic.Int64 // > 64 KiB — would split across multiple 64KB frames
	wrChunkMax   atomic.Int64 // largest single Write seen (bytes)
)

func recordWriteChunk(n int) {
	switch {
	case n <= 8<<10:
		wrChunkLE8K.Add(1)
	case n <= 16<<10:
		wrChunkLE16K.Add(1)
	case n <= 32<<10:
		wrChunkLE32K.Add(1)
	case n <= 64<<10:
		wrChunkLE64K.Add(1)
	default:
		wrChunkGT64K.Add(1)
	}
	for {
		cur := wrChunkMax.Load()
		if int64(n) <= cur || wrChunkMax.CompareAndSwap(cur, int64(n)) {
			break
		}
	}
}

// InHive instrumentation (TEMPORARY — remove once the packet-up chunk starvation is
// fixed). Histogram of packet-up POST payload sizes = what ReadMultiBuffer actually
// hands to each upload POST. This is the number that decides the whole packet-up
// throughput story: with scMinPostsIntervalMs=30 the loop can issue at most ~33
// POSTs/s, so throughput == chunk * 33. Origin access-logs showed exactly 33 req/s
// per session at ~1 Mbit/s, implying ~950 B chunks against a 1 MB allowance — but
// that was inferred from rate x throughput, never measured. This measures it.
// Buckets are deliberately fine at the low end (that is where we expect the mass).
var (
	poChunkLE2K   atomic.Int64 // <= 2 KiB  — one MTU-ish read, the starvation signature
	poChunkLE8K   atomic.Int64 // <= 8 KiB
	poChunkLE32K  atomic.Int64 // <= 32 KiB
	poChunkLE128K atomic.Int64 // <= 128 KiB
	poChunkLE512K atomic.Int64 // <= 512 KiB
	poChunkGT512K atomic.Int64 // > 512 KiB — approaching the 1 MB scMaxEachPostBytes
	poChunkMax    atomic.Int64 // largest single POST payload seen (bytes)
	poChunkCount  atomic.Int64 // total POSTs
	poChunkBytes  atomic.Int64 // total bytes — with count gives the average, the key number
)

// InHive instrumentation (TEMPORARY): xmux state. Answers "did the Xray-parity
// default actually apply, and are we really opening more than one connection?".
// concurrency/connections are what NewXmuxManager resolved; connsCreated counts
// newXmuxClient() calls; liveClients is the current pool size. If connsCreated
// stays at 1 while thousands of POSTs fly, everything is still funnelled into a
// single h2 connection and the parity fix did not take effect.
// retired/reaped (InHive 2026-07-29, фикс зомби-xmux — см. mux.go): до фикса
// пруненные клиенты исчезали из учёта БЕССЛЕДНО (connsCreated=70 при live≤6 на
// 255ч-снимке — 64 «куда-то делись»), и накопление зомби было невидимо. Теперь:
// retired — gauge, сколько пруненных клиентов ещё удерживаются живыми
// стримами/POST'ами (кандидаты в зомби, сумма по всем менеджерам); reaped —
// кумулятивно, сколько пруненных клиентов реально закрыто reaper'ом (Reset не
// считается — это другой механизм). Верификация фикса на живом устройстве без
// 255ч-repro: reaped растёт вместе с connsCreated, retired остаётся малым и
// возвращается к ~0; рост retired без роста reaped = снова копим зомби.
// silentdl (InHive 2026-07-31, детектор глухого download — см. deafwatch.go):
// кумулятивно, сколько раз детектор поймал состояние «download молчит
// >deafSilenceThreshold при активном uplink» (один инкремент на эпизод, не на
// тик). Раньше это состояние было НЕВИДИМО (лог пуст, сессия висит-но-жива);
// теперь rост silentdl на устройстве = подтверждение CDN idle-cut без
// device-repro.
var (
	xmuxConcurrency  atomic.Int64
	xmuxConnections  atomic.Int64
	xmuxConnsCreated atomic.Int64
	xmuxLiveClients  atomic.Int64
	xmuxRetiredGauge atomic.Int64
	xmuxReaped       atomic.Int64
	xhttpSilentDL    atomic.Int64
)

func recordSilentDownload() {
	xhttpSilentDL.Add(1)
}

func recordXmuxConfig(concurrency, connections int32) {
	xmuxConcurrency.Store(int64(concurrency))
	xmuxConnections.Store(int64(connections))
}

func recordXmuxNewConn(liveAfter int) {
	xmuxConnsCreated.Add(1)
	xmuxLiveClients.Store(int64(liveAfter))
}

func recordXmuxPool(live int) {
	xmuxLiveClients.Store(int64(live))
}

// recordXmuxRetired двигает gauge ДЕЛЬТОЙ (+1 retire, -1 sweep, -len(retired)
// на Reset): менеджеров несколько (up/down на каждый Client), Store последнего
// звонившего затирал бы чужие значения — Add суммирует корректно.
func recordXmuxRetired(delta int) {
	xmuxRetiredGauge.Add(int64(delta))
}

func recordXmuxReaped(n int) {
	xmuxReaped.Add(int64(n))
}

// XmuxState returns the current xmux picture for the diag log.
func XmuxState() string {
	return "xmux[concurrency=" + strconv.FormatInt(xmuxConcurrency.Load(), 10) +
		" connections=" + strconv.FormatInt(xmuxConnections.Load(), 10) +
		" connsCreated=" + strconv.FormatInt(xmuxConnsCreated.Load(), 10) +
		" live=" + strconv.FormatInt(xmuxLiveClients.Load(), 10) +
		" retired=" + strconv.FormatInt(xmuxRetiredGauge.Load(), 10) +
		" reaped=" + strconv.FormatInt(xmuxReaped.Load(), 10) +
		" silentdl=" + strconv.FormatInt(xhttpSilentDL.Load(), 10) + "]"
}

func recordPostChunk(n int) {
	switch {
	case n <= 2<<10:
		poChunkLE2K.Add(1)
	case n <= 8<<10:
		poChunkLE8K.Add(1)
	case n <= 32<<10:
		poChunkLE32K.Add(1)
	case n <= 128<<10:
		poChunkLE128K.Add(1)
	case n <= 512<<10:
		poChunkLE512K.Add(1)
	default:
		poChunkGT512K.Add(1)
	}
	poChunkCount.Add(1)
	poChunkBytes.Add(int64(n))
	for {
		cur := poChunkMax.Load()
		if int64(n) <= cur || poChunkMax.CompareAndSwap(cur, int64(n)) {
			break
		}
	}
}

// PostChunkHistogram returns an INTERVAL snapshot (all counters are swapped to 0)
// of packet-up POST sizes, so each emitted line describes only what happened since
// the previous one. Interval — not cumulative — is essential here: the reported
// symptom is upload STARTING fast (~200-300 Mbit/s) and DECAYING to ~1 Mbit/s
// within a single speedtest, and a cumulative average would blend the two and hide
// exactly the transition we need to see.
//
// Reading it: `rate` is the derived throughput for the interval — the number to
// watch decay. `avg` tells us WHY it decays: if avg collapses toward ~1KB the source
// is starving (chunk supply dies); if avg stays large while `n` collapses, the POST
// loop itself is stalling (each POST taking longer). Those are opposite fixes.
func PostChunkHistogram(intervalSec int64) string {
	count := poChunkCount.Swap(0)
	bytes := poChunkBytes.Swap(0)
	le2k := poChunkLE2K.Swap(0)
	le8k := poChunkLE8K.Swap(0)
	le32k := poChunkLE32K.Swap(0)
	le128k := poChunkLE128K.Swap(0)
	le512k := poChunkLE512K.Swap(0)
	gt512k := poChunkGT512K.Swap(0)
	max := poChunkMax.Swap(0)

	var avg int64
	if count > 0 {
		avg = bytes / count
	}
	var kbitPerSec int64
	if intervalSec > 0 {
		kbitPerSec = bytes * 8 / 1000 / intervalSec
	}

	return "xhttp_post[n=" + strconv.FormatInt(count, 10) +
		" avg=" + strconv.FormatInt(avg, 10) +
		"B rate=" + strconv.FormatInt(kbitPerSec, 10) +
		"kbit/s <=2K=" + strconv.FormatInt(le2k, 10) +
		" <=8K=" + strconv.FormatInt(le8k, 10) +
		" <=32K=" + strconv.FormatInt(le32k, 10) +
		" <=128K=" + strconv.FormatInt(le128k, 10) +
		" <=512K=" + strconv.FormatInt(le512k, 10) +
		" >512K=" + strconv.FormatInt(gt512k, 10) +
		" maxK=" + strconv.FormatInt(max/1024, 10) + "]"
}

// ChunkSizeHistogram returns a compact one-line summary for the diag log.
func ChunkSizeHistogram() string {
	return "xhttp_wr[<=8K=" + strconv.FormatInt(wrChunkLE8K.Load(), 10) +
		" <=16K=" + strconv.FormatInt(wrChunkLE16K.Load(), 10) +
		" <=32K=" + strconv.FormatInt(wrChunkLE32K.Load(), 10) +
		" <=64K=" + strconv.FormatInt(wrChunkLE64K.Load(), 10) +
		" >64K=" + strconv.FormatInt(wrChunkGT64K.Load(), 10) +
		" maxK=" + strconv.FormatInt(wrChunkMax.Load()/1024, 10) + "]"
}

// InHive instrumentation 2026-07-19 (TEMPORARY) — счётчики ОТКАЗОВ upload-POST'ов.
//
// Зачем понадобилось: PostPacket возвращает ошибку (в т.ч. `got non-200 error
// response code: 400`), но вызывающий код в client.go делает по ней ТОЛЬКО
// uploadPipeReader.Interrupt() и НИГДЕ её не логирует — апстрим Xray в этом месте
// пишет errors.LogInfoInner(ctx, err, "failed to send upload"), мы это при
// портировании потеряли. Из-за чего upload-половина была полностью слепа: в
// box.log нет ни одной строки про отказ POST'а, и «0 совпадений» в логе ошибочно
// читалось как «отказов нет», хотя access-лог origin показывал 400-е.
//
// Здесь считаем отдельно НЕ-200 и транспортные ошибки, и храним последний текст —
// этого достаточно, чтобы отличить «сервер отвергает наши запросы» от «соединение
// рвётся», не протаскивая logger через конструктор транспорта.
var (
	upErrNon200 atomic.Int64
	upErrOther  atomic.Int64
	upErrLast   atomic.Value // string
)

func recordUploadError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "non-200") {
		upErrNon200.Add(1)
	} else {
		upErrOther.Add(1)
	}
	upErrLast.Store(msg)
}

// UploadErrorState возвращает накопленные счётчики отказов upload-POST'ов.
// Кумулятивно (не интервально): здесь важен сам факт и порядок величины.
func UploadErrorState() string {
	last, _ := upErrLast.Load().(string)
	if len(last) > 160 {
		last = last[:160]
	}
	return "xhttp_uperr[non200=" + strconv.FormatInt(upErrNon200.Load(), 10) +
		" other=" + strconv.FormatInt(upErrOther.Load(), 10) +
		" last=" + strconv.Quote(last) + "]"
}
