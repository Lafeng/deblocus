// +build arm64
// +build cgo

package crypto

import (
	"crypto/cipher"
	"unsafe"
)

//#cgo CFLAGS: -O3 -Wall -I.
//#cgo linux LDFLAGS: -L${SRCDIR} -lcrypto_linux_arm64
//#include "openssl/chacha.h"
import "C"

type ChaCha struct {
	cState *C.chacha_state
	tState *chacha_state_t
}

type chacha_state_t struct {
	state  [16]uint32
	stream [_CHACHA_STREAM_SIZE]byte
	rounds uint
	offset uint
}

func NewChaCha(key, iv []byte, rounds uint) (cipher.Stream, error) {
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

	var s chacha_state_t
	chacha_init(&s.state, key, iv)
	s.rounds = rounds
	s.offset = 0

	cState := (*C.chacha_state)(unsafe.Pointer(&s))
	var chacha = &ChaCha{
		tState: &s,
		cState: cState,
	}
	initStream(chacha)
	return chacha, nil
}

func (c *ChaCha) XORKeyStream(dst, src []byte) {
	cIn := (*C.uint8_t)(unsafe.Pointer(&src[0]))
	cOut := (*C.uint8_t)(unsafe.Pointer(&dst[0]))
	C.CRYPTO_neon_chacha_xor(c.cState, cIn, cOut, C.size_t(len(dst)))
}

func (c *ChaCha) Close() error {
	if c != nil && c.state != nil {
		Memset(&c.tState.state, 64)
		Memset(&c.tState.stream, _CHACHA_STREAM_SIZE)
	}
	return nil
}
