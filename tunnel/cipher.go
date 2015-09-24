package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"github.com/Lafeng/deblocus/exception"
)

var (
	UNSUPPORTED_CIPHER = exception.NewW("Unsupported cipher")
)

type cipherBuilder func(k, iv []byte) *XORCipherKit

type cipherDecr struct {
	keyLen  int
	builder cipherBuilder
}

type cipherKit interface {
	encrypt(dst, src []byte)
	decrypt(dst, src []byte)
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

type NullCipherKit byte

func (c *NullCipherKit) encrypt(dst, src []byte) {}

func (c *NullCipherKit) decrypt(dst, src []byte) {}

var nullCipherKit = new(NullCipherKit)

var availableCiphers = map[string]*cipherDecr{
	"AES128CFB": &cipherDecr{16, newAES_CFB},
	"AES192CFB": &cipherDecr{24, newAES_CFB},
	"AES256CFB": &cipherDecr{32, newAES_CFB},
}

func newAES_CFB(key, iv []byte) *XORCipherKit {
	block, _ := aes.NewCipher(key)
	if iv == nil {
		iv = key[:aes.BlockSize]
	} else {
		iv = iv[:aes.BlockSize]
	}
	ec := cipher.NewCFBEncrypter(block, iv)
	dc := cipher.NewCFBDecrypter(block, iv)
	return &XORCipherKit{ec, dc}
}

type CipherFactory struct {
	key     []byte
	builder cipherBuilder
}

func (c *CipherFactory) InitCipher(iv []byte) *XORCipherKit {
	return c.builder(c.key, iv)
}

func NewCipherFactory(name string, secret []byte) *CipherFactory {
	def := availableCiphers[name]
	key := toSecretKey(secret, def.keyLen)
	return &CipherFactory{
		key, def.builder,
	}
}

func toSecretKey(secret []byte, size int) []byte {
	// size mod 16 must be 0
	h := md5.New()
	buf := make([]byte, size)
	count := size / md5.Size
	// repeatly fill the key with the secret
	for i := 0; i < count; i++ {
		h.Write(secret)
		copy(buf[md5.Size*i:md5.Size*(i+1)-1], h.Sum(nil))
	}
	return buf
}

// single block encrypt
// RSA1024-OAEP_sha1: msg.length <= 86byte
// RSA2048-OAEP_sha1: msg.length <= 214byte
func RSAEncrypt(src []byte, pub *rsa.PublicKey) (enc []byte, err error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, src, nil)
}

// single block decrypt
func RSADecrypt(src []byte, priv *rsa.PrivateKey) (plain []byte, err error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, src, nil)
}

type RSAKeyPair struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

// max length
func RSABlockSize(pub *rsa.PublicKey) int {
	k := (pub.N.BitLen() + 7) / 8
	return k - 2*sha1.Size - 2
}

func GenerateRSAKeyPair(keyBits int) *RSAKeyPair {
	priv, _ := rsa.GenerateKey(rand.Reader, keyBits)
	return &RSAKeyPair{
		priv: priv,
		pub:  &priv.PublicKey,
	}
}
