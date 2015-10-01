package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"github.com/Lafeng/deblocus/crypto"
	"github.com/Lafeng/deblocus/exception"
	"strings"
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

// Uppercase Name
var availableCiphers = []interface{}{
	"AES128CFB", &cipherDecr{16, new_AES_CFB},
	"AES192CFB", &cipherDecr{24, new_AES_CFB},
	"AES256CFB", &cipherDecr{32, new_AES_CFB},
	"CHACHA20", &cipherDecr{32, new_ChaCha20},
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

func new_AES_CFB(key, iv []byte) *XORCipherKit {
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

func new_ChaCha20(key, iv []byte) *XORCipherKit {
	if iv == nil {
		iv = key[:crypto.CHACHA20_IVSize]
	} else {
		iv = iv[:crypto.CHACHA20_IVSize]
	}
	ec, _ := crypto.NewChaCha20(key, iv)
	dc, _ := crypto.NewChaCha20(key, iv)
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
	def, _ := GetAvailableCipher(name)
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
