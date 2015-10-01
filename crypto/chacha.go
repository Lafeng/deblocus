package crypto

import (
	"fmt"
	"os"
	"unsafe"
)

/*
#cgo LDFLAGS: -L${SRCDIR}
#cgo linux,amd64 LDFLAGS: -lchacha_linux_amd64
#cgo windows,amd64 LDFLAGS: -lchacha_windows_amd64
#include "chacha.h"
*/
import "C"

const (
	CHACHA_KeySize   = 32
	CHACHA_BlockSize = 64
	CHACHA20_IVSize  = 8
	CHACHA20_ROUND   = 20
)

type KeySizeError int

func (k KeySizeError) Error() string {
	return fmt.Sprint("crypto/ChaCha: invalid key size", k)
}

func init() {
	n, err := C.chacha_startup()
	if n != 0 {
		fmt.Fprintf(os.Stderr, "chacha_startup=%d err=%v\n", n, err)
	}
}

type ChaCha struct {
	statePtr *C.chacha_state_internal
	keyPtr   *C.chacha_key
	ivPtr    *C.chacha_iv
	state    []byte // raw
}

func NewChaCha20(key, iv []byte) (*ChaCha, error) {
	if ks := len(key); ks != CHACHA_KeySize {
		return nil, KeySizeError(ks)
	}
	leniv := len(iv)
	switch {
	case leniv < CHACHA20_IVSize:
		return nil, KeySizeError(leniv)
	default:
		iv = iv[:CHACHA20_IVSize]
	}

	// use go-copy to imitate chacha_init()
	// but created in go life
	var state [128]byte
	copy(state[:32], key)
	copy(state[40:48], iv)
	statePtr := (*C.chacha_state_internal)(unsafe.Pointer(&state[0]))
	keyPtr := (*C.chacha_key)(unsafe.Pointer(&state[0]))
	ivPtr := (*C.chacha_iv)(unsafe.Pointer(&state[40]))
	statePtr.rounds = CHACHA20_ROUND // important
	// 64:128 buffer
	return &ChaCha{
		statePtr: statePtr,
		keyPtr:   keyPtr,
		ivPtr:    ivPtr,
		state:    state[:],
	}, nil
}

func (c *ChaCha) BlockSize() int {
	return CHACHA_BlockSize
}

func (c *ChaCha) Encrypt(dst, src []byte) {
	size := len(dst)
	if size&0x3f > 0 {
		panic("crypto/chacha: unexpected block size")
	}

	var cIn = (*C.uchar)(unsafe.Pointer(&src[0]))
	var cOut = (*C.uchar)(unsafe.Pointer(&dst[0]))
	C.chacha_update(c.statePtr, cIn, cOut, C.size_t(size))
}

func (c *ChaCha) Decrypt(dst, src []byte) {
	size := len(dst)
	if size&0x3f > 0 {
		panic("crypto/chacha: unexpected block size")
	}

	var cIn = (*C.uchar)(unsafe.Pointer(&src[0]))
	var cOut = (*C.uchar)(unsafe.Pointer(&dst[0]))
	C.chacha_update(c.statePtr, cIn, cOut, C.size_t(size))
}

func (c *ChaCha) XORKeyStream(dst, src []byte) {
	var cIn = (*C.uchar)(unsafe.Pointer(&src[0]))
	var cOut = (*C.uchar)(unsafe.Pointer(&dst[0]))

	C.chacha_next(c.keyPtr, c.ivPtr, cIn, cOut, C.size_t(len(src)), CHACHA20_ROUND)
}
