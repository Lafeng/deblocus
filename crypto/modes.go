package crypto

import (
	"crypto/cipher"
	"errors"
	"fmt"
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
	CHACHA_KeySize   = 32
	CHACHA_BlockSize = 64
	CHACHA_IVSize    = 8
	CHACHA12_ROUND   = 12
	CHACHA20_ROUND   = 20
)

type KeySizeError int

func (k KeySizeError) Error() string {
	return fmt.Sprintf("crypto: invalid key size=%d", k)
}

const (
	_CHACHA_STREAM_SIZE = 512
)

func chacha_init(chachaGrid *[16]uint32, key []byte, nonce []byte) {
	var i, j uint

	chachaGrid[0] = 0x61707865
	chachaGrid[1] = 0x3320646e
	chachaGrid[2] = 0x79622d32
	chachaGrid[3] = 0x6b206574

	// 256 bits key as 8 Little Endian uint32
	for j = 0; j < 8; j++ {
		chachaGrid[j+4] = 0
		for i = 0; i < 4; i++ {
			chachaGrid[j+4] += uint32(key[j*4+i]) << (8 * i)
		}
	}

	// block counter
	chachaGrid[12] = 0
	chachaGrid[13] = 0

	// nonce as 2 consecutives Little Endian uint32
	for j = 0; j < 2; j++ {
		chachaGrid[j+14] = 0
		for i = 0; i < 4; i++ {
			chachaGrid[j+14] += uint32(nonce[j*4+i]) << (8 * i)
		}
	}
}

// force fill xor buffer
func initStream(chacha cipher.Stream) {
	tmp := make([]byte, _CHACHA_STREAM_SIZE)
	chacha.XORKeyStream(tmp, tmp)
}
