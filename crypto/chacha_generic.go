// +build !amd64,!arm64 !cgo

package crypto

import (
	"crypto/cipher"
	"unsafe"
)

type chacha_generic struct {
	state     [16]uint32
	state_ptr *[16]uint32
	stream    [_CHACHA_STREAM_SIZE]byte
	rounds    int
	offset    int
}

func NewChaCha(key, nonce []byte, rounds uint) (cipher.Stream, error) {
	var chacha chacha_generic
	chacha.rounds = int(rounds >> 1)
	chacha.state_ptr = &chacha.state

	chacha_init(chacha.state_ptr, key, nonce)
	initStream(&chacha)
	return &chacha, nil
}

func (c *chacha_generic) BlockSize() int {
	return 64
}

func (c *chacha_generic) Encrypt(dst, in []byte) {
	out := (*[16]uint32)(unsafe.Pointer(&dst[0]))
	chacha_core(out, c.state_ptr, c.rounds)
}

func (c *chacha_generic) Decrypt(dst, in []byte) {
	out := (*[16]uint32)(unsafe.Pointer(&dst[0]))
	chacha_core(out, c.state_ptr, c.rounds)
}

func safeXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

func (c *chacha_generic) XORKeyStream(dst, in []byte) {
	var rem, step, j, inlen int
	j = c.offset
	for inlen = len(dst); inlen > 0; {
		rem = _CHACHA_STREAM_SIZE - j
		if rem <= inlen {
			step = rem
		} else {
			step = inlen
		}
		inlen -= step

		safeXORBytes(dst, in, c.stream[j:])
		dst = dst[step:]
		in = in[step:]
		j += step

		if j == _CHACHA_STREAM_SIZE {
			j, c.offset = 0, 0
			for i := 0; i < _CHACHA_STREAM_SIZE/64; i++ {
				stream_p := (*[16]uint32)(unsafe.Pointer(&c.stream[i*64]))
				chacha_core(stream_p, c.state_ptr, c.rounds)
			}
		} else {
			c.offset = j
		}
	}
}

//
// These methods: chacha_init quarterround chacha_core
// From Romain Jacotin
// Ref: https://github.com/romain-jacotin/ChaCha/blob/master/ChaCha.go

func quarterround(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {

	// quarter-round function performs 4 additions, 4 XORs and 4 bitwise left rotations between 4 choosen uint32 value
	a += b
	d ^= a
	d = d<<16 | d>>16 // this is a bitwise left rotation

	c += d
	b ^= c
	b = b<<12 | b>>20 // this is a bitwise left rotation

	a += b
	d ^= a
	d = d<<8 | d>>24 // this is a bitwise left rotation

	c += d
	b ^= c
	b = b<<7 | b>>25 // this is a bitwise left rotation

	return a, b, c, d
}

func chacha_core(stream, state *[16]uint32, rounds int) {
	var x = *state
	for i := 0; i < rounds; i++ {
		x[0], x[4], x[8], x[12] = quarterround(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = quarterround(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = quarterround(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = quarterround(x[3], x[7], x[11], x[15])

		x[0], x[5], x[10], x[15] = quarterround(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = quarterround(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = quarterround(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = quarterround(x[3], x[4], x[9], x[14])
	}

	stream[0] = x[0] + state[0]
	stream[1] = x[1] + state[1]
	stream[2] = x[2] + state[2]
	stream[3] = x[3] + state[3]
	stream[4] = x[4] + state[4]
	stream[5] = x[5] + state[5]
	stream[6] = x[6] + state[6]
	stream[7] = x[7] + state[7]
	stream[8] = x[8] + state[8]
	stream[9] = x[9] + state[9]
	stream[10] = x[10] + state[10]
	stream[11] = x[11] + state[11]
	stream[12] = x[12] + state[12]
	stream[13] = x[13] + state[13]
	stream[14] = x[14] + state[14]
	stream[15] = x[15] + state[15]

	state[12]++
	if state[12] == 0 {
		state[13]++
	}
}
