package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"github.com/monnand/dhkx"
	"github.com/spance/deblocus/exception"
)

var (
	UNSUPPORTED_CIPHER = exception.NewW("Unsupported cipher method")
)

var cipherLiteral = map[string]int{
	"RC4":       0,
	"AES128CFB": 1,
	"AES256CFB": 2,
}

var cipherDefines = [][]interface{}{
	{newRC4, 16},
	{newAES_CFB, 16},
	{newAES_CFB, 32},
}

func secretToKey(secret []byte, size int) []byte {
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

func newRC4(key, iv []byte) *Cipher {
	ec, _ := rc4.NewCipher(key)
	dc := *ec
	return &Cipher{ec, &dc}
}

func newAES_CFB(key, iv []byte) *Cipher {
	block, _ := aes.NewCipher(key)
	if iv == nil {
		iv = key[:aes.BlockSize]
	} else {
		iv = iv[:aes.BlockSize]
	}
	ec := cipher.NewCFBEncrypter(block, iv)
	dc := cipher.NewCFBDecrypter(block, iv)
	return &Cipher{ec, dc}
}

type Cipher struct {
	enc cipher.Stream
	dec cipher.Stream
}

func (c *Cipher) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *Cipher) decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

type CipherFactory struct {
	key           []byte
	cryptoBuilder func(k, iv []byte) *Cipher
}

func (c *CipherFactory) NewCipher(iv []byte) *Cipher {
	return c.cryptoBuilder(c.key, iv)
}

func NewCipherFactory(id int, secret []byte) *CipherFactory {
	def := cipherDefines[id]
	cc := def[0].(func(k, iv []byte) *Cipher)
	size := def[1].(int)
	key := secretToKey(secret, size)
	return &CipherFactory{
		key, cc,
	}
}

// single block encrypt
// OAEP: must be less than 86byte base on RSA1024-OAEP_sha1
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

func GenerateRSAKeyPair() *RSAKeyPair {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	return &RSAKeyPair{
		priv: priv,
		pub:  &priv.PublicKey,
	}
}

type DHKeyPair struct {
	priv   *dhkx.DHKey
	pub    []byte
	pubLen []byte
}

func GenerateDHKeyPairs() *DHKeyPair {
	// Get a group. Use the default one would be enough.
	g, _ := dhkx.GetGroup(0)
	pair := new(DHKeyPair)
	// Generate a private key from the group.
	// Use the default random number generator.
	priv, _ := g.GeneratePrivateKey(nil)
	pair.priv = priv
	// Get the public key from the private key.
	pair.pub = priv.Bytes()
	pair.pubLen = make([]byte, 2)
	binary.BigEndian.PutUint16(pair.pubLen, uint16(len(pair.pub)))
	return pair
}

func takeSharedKey(pair *DHKeyPair, opub []byte) []byte {
	g, _ := dhkx.GetGroup(0)
	// Recover Bob's public key
	opubkey := dhkx.NewPublicKey(opub)
	// Compute the key
	k, _ := g.ComputeKey(opubkey, pair.priv)
	// Get the key in the form of []byte
	return k.Bytes()
}
