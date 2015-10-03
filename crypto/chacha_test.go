package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"testing"
	"time"
)

var sample, origin []byte

func initChaCha(rounds uint) (*ChaCha, *ChaCha) {
	sample = bytes.Repeat([]byte("abcdefghijklmnopqrstovwxyz1234567890"), 320)
	origin = append([]byte(nil), sample...)

	key := make([]byte, 32)
	iv := make([]byte, 8)
	io.ReadFull(rand.Reader, key)
	io.ReadFull(rand.Reader, iv)
	chacha20_1, _ := NewChaCha(key, iv, rounds)
	chacha20_2, _ := NewChaCha(key, iv, rounds)
	return chacha20_1, chacha20_2
}

func Benchmark_ChaCha8_xor(b *testing.B) {
	ec, _ := initChaCha(8)
	b.SetBytes(int64(len(sample)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_ChaCha12_xor(b *testing.B) {
	ec, _ := initChaCha(12)
	b.SetBytes(int64(len(sample)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_ChaCha20_xor(b *testing.B) {
	ec, _ := initChaCha(20)
	b.SetBytes(int64(len(sample)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES128_cfb(b *testing.B) {
	key := sample[:16]
	b.SetBytes(int64(len(sample)))
	block, _ := aes.NewCipher(key)
	ec := cipher.NewCFBEncrypter(block, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES192_cfb(b *testing.B) {
	key := sample[:24]
	b.SetBytes(int64(len(sample)))
	block, _ := aes.NewCipher(key)
	ec := cipher.NewCFBEncrypter(block, key[:16])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES256_cfb(b *testing.B) {
	key := sample[:32]
	b.SetBytes(int64(len(sample)))
	block, _ := aes.NewCipher(key)
	ec := cipher.NewCFBEncrypter(block, key[:16])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_ChaCha20_block(b *testing.B) {
	ec, _ := initChaCha(20)
	blockLen := len(sample) >> 6 << 6
	block := sample[:blockLen]
	b.SetBytes(int64(len(block)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.Encrypt(block, block)
	}
}

func Benchmark_AES256_block(b *testing.B) {
	key := sample[:32]
	b.SetBytes(int64(len(sample)))
	ec, _ := aes.NewCipher(key)
	var tmp []byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(sample); j += 16 {
			tmp = sample[j : j+16]
			ec.Encrypt(tmp, tmp) // one-block encryptBlockAsm()
		}
	}
}

func TestChaChaCorrectness(t *testing.T) {
	ec, dc := initChaCha(20)
	sample = bytes.Repeat(origin, 100)
	origin = bytes.Repeat(origin, 100)

	randChip("dec", sample, func(chip []byte) {
		ec.XORKeyStream(chip, chip)
	})

	dc.XORKeyStream(sample, sample)

	if !bytes.Equal(origin, sample) {
		dumpHex(sample, "result")
		dumpHex(origin, "origin")
		t.Fatalf("Incorrect result")
	}

	ec.XORKeyStream(sample, sample)

	randChip("dec", sample, func(chip []byte) {
		dc.XORKeyStream(chip, chip)
	})

	if !bytes.Equal(origin, sample) {
		dumpHex(sample, "result")
		dumpHex(origin, "origin")
		t.Fatalf("Incorrect result")
	}
}

func dumpHex(data []byte, label string) {
	fmt.Fprintln(os.Stdout, "------ dump ------", label)
	fmt.Fprintln(os.Stdout, hex.Dump(data))
}

func randChip(label string, sample []byte, call func(chip []byte)) {
	mrand.Seed(int64(time.Now().Nanosecond()))

	for i := 0; i < len(sample); {
		rem := len(sample) - i
		s := mrand.Int() % rem
		if s == 0 {
			s = rem
		}
		smp := sample[i : i+s]
		call(smp)
		//		dumpHex(smp, label+" chip")
		i += s
	}
}
