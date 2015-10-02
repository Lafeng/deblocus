// +build cgo AND amd64

package crypto

import (
	"fmt"
	"os"
	"unsafe"
)

/*
#cgo CFLAGS: -O3
#cgo LDFLAGS: -L${SRCDIR}
#cgo linux LDFLAGS: -Wl,--wrap=memcpy -lchacha_linux_amd64
#cgo windows LDFLAGS: -lchacha_windows_amd64
#cgo darwin LDFLAGS: -lchacha_darwin_amd64
#include "chacha.h"
*/
import "C"

const (
	CHACHA_KeySize   = 32
	CHACHA_BlockSize = 64
	CHACHA_IVSize    = 8
	CHACHA12_ROUND   = 12
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

func NewChaCha(key, iv []byte, rounds uint) (*ChaCha, error) {
	if ks := len(key); ks != CHACHA_KeySize {
		return nil, KeySizeError(ks)
	}
	ivLen := len(iv)
	switch {
	case ivLen < CHACHA_IVSize:
		return nil, KeySizeError(ivLen)
	case ivLen == CHACHA_IVSize:
	default:
		iv = iv[:CHACHA_IVSize]
	}

	// create chacha_state_internal like chacha_init()
	var state [128 + 64 + 8]byte
	copy(state[:32], key)
	copy(state[40:48], iv)
	statePtr := (*C.chacha_state_internal)(unsafe.Pointer(&state[0]))
	keyPtr := (*C.chacha_key)(unsafe.Pointer(statePtr))
	ivPtr := (*C.chacha_iv)(unsafe.Pointer(&state[40]))
	statePtr.rounds = C.size_t(rounds) // important
	statePtr.offset = 0

	var chacha = &ChaCha{
		statePtr: statePtr,
		keyPtr:   keyPtr,
		ivPtr:    ivPtr,
		state:    state[:],
	}
	chacha.initStream()
	return chacha, nil
}

// implement cipher.Block interface
func (c *ChaCha) BlockSize() int {
	return CHACHA_BlockSize
}

// implement cipher.Block interface
func (c *ChaCha) Encrypt(dst, src []byte) {
	size := len(dst)
	if size&0x3f > 0 {
		panic("crypto/chacha: unexpected block size")
	}

	var cIn = (*C.uchar)(unsafe.Pointer(&src[0]))
	var cOut = (*C.uchar)(unsafe.Pointer(&dst[0]))
	C.chacha_update(c.statePtr, cIn, cOut, C.size_t(size))
}

// implement cipher.Block interface
func (c *ChaCha) Decrypt(dst, src []byte) {
	size := len(dst)
	if size&0x3f > 0 {
		panic("crypto/chacha: unexpected block size")
	}

	var cIn = (*C.uchar)(unsafe.Pointer(&src[0]))
	var cOut = (*C.uchar)(unsafe.Pointer(&dst[0]))
	C.chacha_update(c.statePtr, cIn, cOut, C.size_t(size))
}

// implement cipher.Stream interface
func (c *ChaCha) XORKeyStream(dst, src []byte) {
	var cIn = (*C.uchar)(unsafe.Pointer(&src[0]))
	var cOut = (*C.uchar)(unsafe.Pointer(&dst[0]))
	C.chacha_xor(c.statePtr, cIn, cOut, C.size_t(len(dst)))
}

func (c *ChaCha) initStream() {
	copy(c.state[128:], sbox0)
	buf := make([]byte, CHACHA_BlockSize)
	c.XORKeyStream(buf, buf)
}

var sbox0 = []byte{
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
}
