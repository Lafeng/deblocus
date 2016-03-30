// +build !amd64,!arm64 !cgo

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

type aesNativeCipher struct {
	cipher.Block
	mode BLOCK_MODE
}

func NewAESCipher(key []byte, mode BLOCK_MODE) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err == nil {
		return &aesNativeCipher{block, mode}, nil
	} else {
		return nil, err
	}
}

func NewAESEncrypter(block cipher.Block, iv []byte) (cipher.Stream, error) {
	aes := block.(*aesNativeCipher)
	switch aes.mode & 0xff {
	case MODE_OFB:
		return cipher.NewOFB(aes, iv), nil
	case MODE_CFB:
		return cipher.NewCFBEncrypter(block, iv), nil
	case MODE_CTR:
		return cipher.NewCTR(block, iv), nil
	}
	return nil, ERR_NOT_IMPLEMENTED
}

func NewAESDecrypter(block cipher.Block, iv []byte) (cipher.Stream, error) {
	aes := block.(*aesNativeCipher)
	switch aes.mode & 0xff {
	case MODE_OFB:
		return cipher.NewOFB(aes, iv), nil
	case MODE_CFB:
		return cipher.NewCFBDecrypter(block, iv), nil
	case MODE_CTR:
		return cipher.NewCTR(block, iv), nil
	}
	return nil, ERR_NOT_IMPLEMENTED
}

// compat impl.
func HasAESHardware() int {
	return 0
}

func IsNEONCapable() int {
	return 0
}

func GetCpuid() []uint32 {
	return nil
}
