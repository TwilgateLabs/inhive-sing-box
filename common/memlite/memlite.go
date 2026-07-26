// Package memlite — дешёвое чтение памяти Go-рантайма через runtime/metrics,
// БЕЗ stop-the-world.
//
// InHive 2026-07-26. Зачем: sing/common/memory.Inuse() делает полный
// runtime.ReadMemStats — это STW всех горутин. У нас он сидел на секундных
// тиках (GetSystemInfoStream → hcore readStatus; clash Snapshot на открытой
// вкладке «Соединения»; daemon.ReadStatus на не-darwin) — т.е. ядро само
// дёргало себя stop-the-world раз в секунду всё время, пока открыто окно
// приложения. На iOS NE с GOMAXPROCS=1 это секундный микро-джиттер поверх
// туннеля.
//
// СЕМАНТИКА СОХРАНЕНА ТОЧНО, цифра в UI не меняется. Тождество по документации
// runtime/metrics (соответствия метрик полям MemStats):
//
//	HeapInuse    = /memory/classes/heap/objects + /memory/classes/heap/unused
//	HeapIdle     = /memory/classes/heap/free    + /memory/classes/heap/released
//	HeapReleased = /memory/classes/heap/released
//	StackInuse   = /memory/classes/heap/stacks
//
//	memory.Inuse() = StackInuse + HeapInuse + HeapIdle − HeapReleased
//	               = stacks + objects + unused + free (+released − released)
//	               = сумма четырёх метрик ниже.
//
// SIBLINGS: тот же приём (runtime/metrics вместо ReadMemStats, с тем же
// обоснованием «дешевле, без STW») — v2/hcore/mem_sampler.go.
package memlite

import "runtime/metrics"

// Слайс сэмплов аллоцируется на каждый вызов НАМЕРЕННО: metrics.Read пишет в
// Value, общий пакетный слайс дал бы data race между конкурентными читателями
// (SystemInfo-стрим и clash Snapshot тикают независимо). 4 структуры на вызов —
// копейки против снятого STW.

// Inuse — тот же смысл (и та же цифра), что sing/common/memory.Inuse():
// Stack + HeapInuse + HeapIdle − HeapReleased, но без stop-the-world.
func Inuse() uint64 {
	s := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/unused:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
		{Name: "/memory/classes/heap/stacks:bytes"},
	}
	metrics.Read(s)
	var total uint64
	for i := range s {
		if s[i].Value.Kind() == metrics.KindUint64 {
			total += s[i].Value.Uint64()
		}
	}
	return total
}

// HeapAlloc — эквивалент MemStats.HeapAlloc (живые heap-объекты) без STW:
// /memory/classes/heap/objects:bytes. Потребитель — heartbeatLoop
// (grpc_server.go), печатавший heap=HeapAlloc MB.
func HeapAlloc() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() == metrics.KindUint64 {
		return s[0].Value.Uint64()
	}
	return 0
}
