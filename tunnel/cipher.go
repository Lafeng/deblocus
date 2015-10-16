package tunnel

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"github.com/Lafeng/deblocus/crypto"
	"github.com/Lafeng/deblocus/exception"
	"io"
	"strings"
)

var (
	UNSUPPORTED_CIPHER = exception.NewW("Unsupported cipher")
)

type cipherBuilder func(k, iv []byte) *XORCipherKit

type cipherDecr struct {
	keyLen  int
	ivLen   int
	builder cipherBuilder
}

type cipherKit interface {
	encrypt(dst, src []byte)
	decrypt(dst, src []byte)
	Cleanup()
}

type XORCipherKit struct {
	enc cipher.Stream
	dec cipher.Stream
}

func (c *XORCipherKit) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *XORCipherKit) decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

func (c *XORCipherKit) Cleanup() {
	if clean, y := c.enc.(io.Closer); y {
		clean.Close()
	}
	if clean, y := c.dec.(io.Closer); y {
		clean.Close()
	}
}

type NullCipherKit byte

func (c *NullCipherKit) encrypt(dst, src []byte) {}
func (c *NullCipherKit) decrypt(dst, src []byte) {}
func (c *NullCipherKit) Cleanup()                {}

var nullCipherKit = new(NullCipherKit)

// Uppercase Name
var availableCiphers = []interface{}{
	"CHACHA12", &cipherDecr{32, 8, new_ChaCha12},
	"CHACHA20", &cipherDecr{32, 8, new_ChaCha20},
	"AES128OFB", &cipherDecr{16, 16, new_AES_OFB},
	"AES256OFB", &cipherDecr{32, 16, new_AES_OFB},
	"AES128CTR", &cipherDecr{16, 16, new_AES_CTR},
	"AES192CTR", &cipherDecr{24, 16, new_AES_CTR},
	"AES256CTR", &cipherDecr{32, 16, new_AES_CTR},
}

func GetAvailableCipher(wants string) (*cipherDecr, error) {
	wants = strings.ToUpper(wants)
	for i := 0; i < len(availableCiphers); i += 2 {
		name := availableCiphers[i].(string)
		decr := availableCiphers[i+1].(*cipherDecr)
		if name == wants {
			return decr, nil
		}
	}
	return nil, UNSUPPORTED_CIPHER.Apply(wants)
}

func new_AES_CTR(key, iv []byte) *XORCipherKit {
	block, _ := crypto.NewAESCipher(key, crypto.MODE_CTR)
	ec, _ := crypto.NewAESEncrypter(block, iv)
	dc, _ := crypto.NewAESDecrypter(block, iv)
	return &XORCipherKit{ec, dc}
}

func new_AES_OFB(key, iv []byte) *XORCipherKit {
	block, _ := crypto.NewAESCipher(key, crypto.MODE_OFB)
	ec, _ := crypto.NewAESEncrypter(block, iv)
	dc, _ := crypto.NewAESDecrypter(block, iv)
	return &XORCipherKit{ec, dc}
}

func new_ChaCha20(key, iv []byte) *XORCipherKit {
	ec, e := crypto.NewChaCha(key, iv, crypto.CHACHA20_ROUND)
	ThrowErr(e)
	dc, e := crypto.NewChaCha(key, iv, crypto.CHACHA20_ROUND)
	ThrowErr(e)
	return &XORCipherKit{ec, dc}
}

func new_ChaCha12(key, iv []byte) *XORCipherKit {
	ec, e := crypto.NewChaCha(key, iv, crypto.CHACHA12_ROUND)
	ThrowErr(e)
	dc, e := crypto.NewChaCha(key, iv, crypto.CHACHA12_ROUND)
	ThrowErr(e)
	return &XORCipherKit{ec, dc}
}

type CipherFactory struct {
	key, ref []byte
	decr     *cipherDecr
}

func (c *CipherFactory) InitCipher(iv []byte) *XORCipherKit {
	if iv == nil {
		iv = normalizeKey(c.key, c.ref, c.decr.ivLen)
	} else {
		iv = normalizeKey(iv, c.ref, c.decr.ivLen)
	}
	return c.decr.builder(c.key, iv)
}

func (f *CipherFactory) Cleanup() {
	crypto.Memset(f.key, 0)
	crypto.Memset(f.ref, 0)
}

func NewCipherFactory(name string, secret []byte) *CipherFactory {
	def, _ := GetAvailableCipher(name)
	ref := hash20(secret)
	key := normalizeKey(secret, ref, def.keyLen)
	return &CipherFactory{
		key, ref, def,
	}
}

func normalizeKey(raw, ref []byte, size int) []byte {
	hs := sha256.New()
	count := (size + 31) >> 5
	step := len(raw) / count
	key := make([]byte, 0, count<<5)
	for i, j := 0, 0; i < count; i, j = i+1, j+step {
		hs.Write(raw[j : j+step])
		if i == 0 && ref != nil {
			hs.Write(ref)
		} else {
			hs.Write(key)
		}
		key = hs.Sum(key)
	}
	return key[:size]
}

// single block encrypt
// RSA1024-OAEP_sha1: msg.length <= 86byte
// RSA2048-OAEP_sha1: msg.length <= 214byte
func (k *RSAKeyPair) Encrypt(src []byte) (enc []byte, err error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, k.pub, src, nil)
}

// single block decrypt
func (k *RSAKeyPair) Decrypt(src []byte) (plain []byte, err error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, k.priv, src, nil)
}

type RSAKeyPair struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

// max length of encryption
func (k *RSAKeyPair) BlockSize() int {
	K := (k.pub.N.BitLen() + 7) / 8
	return K - 2*sha1.Size - 2
}

func (k *RSAKeyPair) SharedKey() []byte {
	return k.pub.N.Bytes()
}

func GenerateRSAKeyPair(keyBits int) *RSAKeyPair {
	priv, _ := rsa.GenerateKey(rand.Reader, keyBits)
	return &RSAKeyPair{
		priv: priv,
		pub:  &priv.PublicKey,
	}
}
