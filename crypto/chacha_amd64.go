// +build amd64
// +build cgo

package crypto

import (
	"fmt"
	"os"
	"unsafe"
)

/*
#cgo CFLAGS: -O3 -Wall -Werror
#cgo LDFLAGS: -L${SRCDIR}
#cgo linux LDFLAGS: -Wl,--wrap=memcpy -lchacha_linux_amd64
#cgo windows LDFLAGS: -lchacha_windows_amd64
#cgo darwin LDFLAGS: -lchacha_darwin_amd64
#include "chacha_amd64.h"
*/
import "C"

func init() {
	n, err := C.chacha_startup()
	if n != 0 {
		fmt.Fprintf(os.Stderr, "chacha_startup=%d err=%v\n", n, err)
	}
}

type chacha_state struct {
	s        [48]byte
	rounds   uintptr
	leftover uintptr
	buffer   [CHACHA_BlockSize]byte
	stream   [_CHACHA_STREAM_SIZE]byte
	offset   uintptr
}

type ChaCha struct {
	statePtr *C.chacha_state_internal
	state    *chacha_state
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
	var state chacha_state
	copy(state.s[:32], key)
	copy(state.s[40:48], iv)
	state.leftover = 0
	state.offset = 0
	state.rounds = uintptr(rounds) // important
	statePtr := (*C.chacha_state_internal)(unsafe.Pointer(&state))

	var chacha = &ChaCha{
		statePtr: statePtr,
		state:    &state,
	}
	chacha.initStream(iv)
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

func (c *ChaCha) initStream(iv []byte) {
	stream := c.state.stream
	var x uint16
	iv = iv[:cap(iv)]
	for i := 0; i < 256; i++ {
		x = uint16(sbox0[i]) * uint16(iv[i%len(iv)])
		stream[2*i] = byte(x >> 8)
		stream[2*i+1] = byte(x)
	}
	buf := make([]byte, _CHACHA_STREAM_SIZE)
	c.XORKeyStream(buf, buf)
}
