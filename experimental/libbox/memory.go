package libbox

import (
	"math"
	"runtime"
	runtimeDebug "runtime/debug"

	C "github.com/sagernet/sing-box/constant"
)

var memoryLimitEnabled bool

func SetMemoryLimit(enabled bool) {
	memoryLimitEnabled = enabled
	// Цель — удержать RSS под ~45MB (запас под жёсткий потолок iOS
	// packet-tunnel в 50MB по phys_footprint). Прежние 45MB Go-heap давали
	// ~60-75MB RSS — это вылетало за линию и загоняло рантайм в вечный
	// GC-assist (death-spiral) вместо чистого килла. 32MB heap-target
	// возвращает ~30MB эффективного headroom.
	const memoryLimitGo = 32 * 1024 * 1024
	if enabled {
		if C.IsIos {
			// GOGC=30 — ТОЛЬКО iOS. 10% был hair-trigger у самого лимита (GC
			// дёргался непрерывно); 30% даёт рантайму дышать, не упираясь в стенку.
			//
			// Почему именно iOS: смысл у этого числа появляется исключительно в
			// паре с SetMemoryLimit(32MB) ниже — удержать RSS под ~45MB, чтобы
			// jetsam не убил packet-tunnel с бюджетом 50MB.
			//
			// InHive 2026-07-19: строка стояла ВЫШЕ этого гейта и втихую била по
			// Android/Windows — при том, что комментарий ниже прямо гласит
			// «Android/Windows НЕ трогаем: там RAM есть и пропускная важнее».
			// Намерение было записано, код ему противоречил. На десктопе, где
			// лимита памяти нет, GOGC=30 означает просто в ~3.3 раза более частый
			// GC: лишние STW-паузы и джиттер pacing'а на 200+ Мбит/с, ноль пользы.
			// Референсный клиент (Happ/Xray) живёт на стоковом GOGC=100.
			runtimeDebug.SetGCPercent(30)
			runtimeDebug.SetMemoryLimit(memoryLimitGo)
			// GOMAXPROCS=1 только на iOS NE. Каждый рантайм-P держит OS-тред,
			// а каждый тред-стек жрёт phys_footprint (по которому jetsam решает
			// убить packet-tunnel при бюджете ~15-50MB). На многоядерном iPhone
			// дефолтный GOMAXPROCS=число ядер раздувает число тредов на пустом
			// месте — для VPN-прокси (I/O-bound, не CPU-bound) параллелизм почти
			// не нужен, а экономия footprint критична. Android/Windows НЕ трогаем:
			// там RAM есть и пропускная способность важнее. Подход подсмотрен у
			// Tailscale iOS NE (та же борьба за 15MB).
			runtime.GOMAXPROCS(1)
			// P1-b (2026-07-02): жёсткий потолок на число OS-тредов. Дефолт
			// Go — 10000. При потере upstream каждый заблокированный в cgo
			// dial (ProtectFunc / DNS-резолв в Swift) может держать свой тред,
			// а TCP-путь до P1-a был вообще не капнут (в отличие от DNS-обмена).
			// 10000 тредов = GB address space + phys_footprint по тред-стекам →
			// на 50MB NE-бюджете это либо jetsam, либо неконтролируемый
			// `fatal error: thread exhaustion` (SIGABRT без gopanic-фрейма —
			// ровно почерк краша 4.6.0 b71 на маке 2026-07-02). 512 конвертит
			// это в ранний, детерминированный, логируемый отказ; в паре с
			// dial-cap (P1-a, maxConcurrentDials=256) практически недостижим.
			runtimeDebug.SetMaxThreads(512)
		}
	} else {
		// 100 = сток Go. На не-iOS это no-op (мы там GOGC и не трогали, см. гейт
		// выше), на iOS — возврат к дефолту. Гейт здесь не нужен: восстановление
		// стокового значения безопасно на любой платформе.
		runtimeDebug.SetGCPercent(100)
		if C.IsIos {
			runtimeDebug.SetMemoryLimit(math.MaxInt64)
		}
	}
}
