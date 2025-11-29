package guest

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/mcuadros/go-defaults"
)

func BytesFrom(ptr, size uint32) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

func PtrToString(ptr uint32, size uint32) string {
	return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

func StringToPtr(s string) (uint32, uint32) {
	ptr := unsafe.Pointer(unsafe.StringData(s))
	return uint32(uintptr(ptr)), uint32(len(s))
}

func ReadRequest[T any](ptr, size uint32) (*T, error) {
	in := BytesFrom(ptr, size)
	if len(in) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	var req T
	defaults.SetDefaults(&req)
	if err := json.Unmarshal(in, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func WriteResponse[T any](resp *T, outputPtr, outputMaxLen uint32) (int32, error) {
	out, err := json.Marshal(resp)
	if err != nil {
		return -2, fmt.Errorf("json marshal failed: %w", err)
	}
	// write host memory
	if uint32(len(out)) > outputMaxLen {
		return -4, fmt.Errorf("output buffer too small")
	}
	dst := BytesFrom(outputPtr, outputMaxLen)
	copy(dst, out)
	return int32(len(out)), nil
}
