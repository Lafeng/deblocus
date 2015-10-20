package crypto

import (
	"unsafe"
)

const (
	offset32 uint32 = 2166136261
	prime32  uint32 = 16777619
)

// hash the head 6-byte of [data].
// altered from fnv32a
func Hash16Of6(data []byte) uint16 {
	hash := offset32
	ptr := (uintptr)(unsafe.Pointer(&data[0]))
	u32 := *(*uint32)(unsafe.Pointer(ptr))
	hash ^= uint32(u32)
	hash *= prime32
	u16 := *(*uint16)(unsafe.Pointer(ptr + 4))
	hash ^= uint32(u16)
	hash *= prime32
	return uint16((hash >> 16) ^ hash)
}

func SetHash16At6(data []byte) {
	h := Hash16Of6(data)
	data[6] = byte(h >> 8)
	data[7] = byte(h)
}

func VerifyHash16At6(data []byte) bool {
	h1 := Hash16Of6(data)
	h2 := uint16(data[6])<<8 | uint16(data[7])
	return h1 == h2
}
