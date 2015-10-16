package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"unsafe"
)

type BLOCK_MODE uint32

const (
	MODE_ENCRYPT BLOCK_MODE = 0x1 << 16
	MODE_DECRYPT BLOCK_MODE = 0x2 << 16
	MODE_CTR     BLOCK_MODE = 0x1
	MODE_OFB     BLOCK_MODE = 0x2
	MODE_CFB     BLOCK_MODE = 0x3
	MODE_CBC     BLOCK_MODE = 0x11
	MODE_AEAD    BLOCK_MODE = 0x21
)

const (
	AES_BLOCK_SIZE = 16
)

var (
	ERR_BAD_KEY_LENGTH  = errors.New("BAD_KEY_LENGTH")
	ERR_BAD_IV_LENGTH   = errors.New("BAD_IV_LENGTH")
	ERR_NOT_IMPLEMENTED = errors.New("ERR_NOT_IMPLEMENTED")
)

const (
	CHACHA_KEY_SIZE   = 32
	CHACHA_BLOCK_SIZE = 64
	CHACHA_IV_SIZE    = 8
	CHACHA12_ROUND    = 12
	CHACHA20_ROUND    = 20
)

type KeySizeError int

func (k KeySizeError) Error() string {
	return fmt.Sprintf("crypto: invalid key size=%d", k)
}

const (
	_CHACHA_STREAM_SIZE = 512
)

func chacha_init(chachaGrid *[16]uint32, key []byte, nonce []byte) {
	chachaGrid[0] = 0x61707865
	chachaGrid[1] = 0x3320646e
	chachaGrid[2] = 0x79622d32
	chachaGrid[3] = 0x6b206574

	// 256 bits key as 8 Little Endian uint32
	for j := 0; j < 8; j++ {
		chachaGrid[j+4] = binary.LittleEndian.Uint32(key[j*4:])
	}
	// block counter
	chachaGrid[12] = 0
	chachaGrid[13] = 0
	// nonce as 2 consecutives Little Endian uint32
	chachaGrid[14] = binary.LittleEndian.Uint32(nonce)
	chachaGrid[15] = binary.LittleEndian.Uint32(nonce[4:])
}

// force filling xor buffer
func initStream(chacha cipher.Stream) {
	tmp := make([]byte, _CHACHA_STREAM_SIZE)
	chacha.XORKeyStream(tmp, tmp)
}

// set the ref represented memory area to zero
// if ref is a slice, use len(slice) instead of length arg.
// if ref is a pointer of array, length must be the actual length of array.
func Memset(ref interface{}, length int) {
	var dst []byte

	switch ref.(type) {
	case []byte:
		dst = ref.([]byte)
		length = len(dst)

	case []uint32:
		origin := ref.([]uint32)
		length = len(origin) * 4
		arrayPtr := (uintptr)(unsafe.Pointer(&origin[0]))
		newSlice := reflect.SliceHeader{arrayPtr, length, length}
		dst = *(*[]byte)(unsafe.Pointer(&newSlice))

	default: // assumed ref is a pointer
		arrayPtr := reflect.ValueOf(ref).Pointer()
		newSlice := reflect.SliceHeader{arrayPtr, length, length}
		dst = *(*[]byte)(unsafe.Pointer(&newSlice))

	}

	zero := make([]byte, 16)
	for i := 0; i < length; {
		i += copy(dst[i:], zero)
	}
}
