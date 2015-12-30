package tunnel

import (
	stdcrypto "crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/Lafeng/deblocus/crypto"
	"github.com/Lafeng/deblocus/exception"
)

var (
	UNSUPPORTED_CIPHER = exception.New("Unsupported cipher")
)

type cipherBuilder func(k, iv []byte) *XORCipherKit

type cipherDesc struct {
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
	"CHACHA12", &cipherDesc{32, 8, new_ChaCha12},
	"CHACHA20", &cipherDesc{32, 8, new_ChaCha20},
	"AES128OFB", &cipherDesc{16, 16, new_AES_OFB},
	"AES256OFB", &cipherDesc{32, 16, new_AES_OFB},
	"AES128CTR", &cipherDesc{16, 16, new_AES_CTR},
	"AES192CTR", &cipherDesc{24, 16, new_AES_CTR},
	"AES256CTR", &cipherDesc{32, 16, new_AES_CTR},
}

func GetAvailableCipher(wants string) (*cipherDesc, error) {
	wants = strings.ToUpper(wants)
	for i := 0; i < len(availableCiphers); i += 2 {
		name := availableCiphers[i].(string)
		decr := availableCiphers[i+1].(*cipherDesc)
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
	key  []byte
	decr *cipherDesc
}

func (c *CipherFactory) InitCipher(iv []byte) *XORCipherKit {
	if iv == nil {
		panic("iv nil") // TODO test
	}
	if len(iv) < c.decr.ivLen {
		iv = normalizeKey(c.decr.ivLen, iv)
	} else {
		iv = iv[:c.decr.ivLen]
	}
	return c.decr.builder(c.key, iv)
}

func (f *CipherFactory) Cleanup() {
	crypto.Memset(f.key, 0)
}

func NewCipherFactory(name string, secrets ...[]byte) *CipherFactory {
	desc, _ := GetAvailableCipher(name)
	key := normalizeKey(desc.keyLen, secrets...)
	return &CipherFactory{key, desc}
}

func normalizeKey(size int, msg ...[]byte) []byte {
	hs := sha256.New()
	for _, m := range msg {
		hs.Write(m)
	}
	key := hs.Sum(nil)
	return key[:size]
}

func NameOfKey(v interface{}) string {
	switch k := v.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECC-P%d", k.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	}
	return NULL
}

func GenerateECCKey(name string) (stdcrypto.PrivateKey, error) {
	if name == NULL {
		name = "ECC-P256"
	}
	curve, err := crypto.SelectCurve(name)
	if err != nil {
		return nil, err
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func MarshalPrivateKey(priv stdcrypto.PrivateKey) (b []byte) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		b = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		b, _ = x509.MarshalECPrivateKey(k)
	}
	return
}

func UnmarshalPrivateKey(b []byte) (stdcrypto.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(b); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return k, nil
	}
	return nil, UNRECOGNIZED_SYMBOLS
}

func preSharedKey(v interface{}) []byte {
	switch k := v.(type) {
	case *rsa.PublicKey:
		return k.N.Bytes()
	case *ecdsa.PublicKey:
		return k.X.Bytes()
	}
	return nil
}

func MarshalPublicKey(v interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(v)
}

func UnmarshalPublicKey(b []byte) (stdcrypto.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(b)
	if pub == nil { //maybe pub==err==nil
		return nil, nvl(err, UNRECOGNIZED_SYMBOLS).(error)
	}
	return pub.(stdcrypto.PublicKey), nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func DS_Verify(pub stdcrypto.PublicKey, sig, msg []byte) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return nil == rsa.VerifyPKCS1v15(k, stdcrypto.SHA256, msg, sig)
	case *ecdsa.PublicKey:
		var es ecdsaSignature
		_, err := asn1.Unmarshal(sig, &es)
		if err != nil {
			return false
		}
		return ecdsa.Verify(k, msg, es.R, es.S)
	}
	panic("unknow key")
}

func DS_Sign(priv stdcrypto.PrivateKey, msg []byte) []byte {
	if signer, y := priv.(stdcrypto.Signer); y {
		b, err := signer.Sign(rand.Reader, msg, nil)
		ThrowErr(err)
		return b
	}
	return nil
}
