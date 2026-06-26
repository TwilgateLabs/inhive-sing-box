//go:build !darwin || !cgo

package libbox

// PhysFootprintBytes на не-darwin (или darwin без cgo) недоступен — phys_footprint
// это macOS/iOS-специфичная метрика task_vm_info. Возвращаем 0; сэмплер в этом
// случае просто не печатает поле footprint (см. v2/hcore/mem_sampler.go).
func PhysFootprintBytes() uint64 {
	return 0
}
