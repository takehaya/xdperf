package goshim

//go:wasmexport malloc
func malloc(size uint32) uint32 {
	return 0
}

//go:wasmexport free
func free(ptr uint32) {}
