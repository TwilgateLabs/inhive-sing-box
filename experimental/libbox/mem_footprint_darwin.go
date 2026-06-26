//go:build darwin && cgo

package libbox

/*
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/task_info.h>

// readPhysFootprint возвращает phys_footprint текущего процесса в байтах
// (0 при ошибке). Это та самая метрика, по которой iOS jetsam решает убить
// packet-tunnel — она ближе к реальному RSS, чем Go-heap, потому что
// учитывает нативные аллокации (tun, сокеты, libdispatch и т.п.). Для
// диагностики на устройстве (без Xcode) она важнее, чем runtime.ReadMemStats.
static unsigned long long readPhysFootprint() {
	task_vm_info_data_t info;
	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	kern_return_t kr = task_info(mach_task_self(), TASK_VM_INFO,
		(task_info_t)&info, &count);
	if (kr != KERN_SUCCESS) {
		return 0;
	}
	return (unsigned long long)info.phys_footprint;
}
*/
import "C"

// PhysFootprintBytes — phys_footprint процесса в байтах, или 0 если прочитать
// не удалось. Доступно только под darwin+cgo (iOS/macOS); на остальных
// платформах см. mem_footprint_other.go (возвращает 0).
func PhysFootprintBytes() uint64 {
	return uint64(C.readPhysFootprint())
}
