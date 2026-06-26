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
		// 10% был hair-trigger у самого лимита (GC дёргался непрерывно);
		// 30% даёт рантайму дышать, не упираясь в стенку.
		runtimeDebug.SetGCPercent(30)
		if C.IsIos {
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
		}
	} else {
		runtimeDebug.SetGCPercent(100)
		if C.IsIos {
			runtimeDebug.SetMemoryLimit(math.MaxInt64)
		}
	}
}
