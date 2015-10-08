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

	key := make([]byte, 40)
	io.ReadFull(rand.Reader, key)
	chacha_1, _ := NewChaCha(key[:32], key[32:], rounds)
	chacha_2, _ := NewChaCha(key[:32], key[32:], rounds)
	return chacha_1, chacha_2
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

func test_correctness(t *testing.T, ec, dc *ChaCha, sample2, origin2 []byte) {
	// n-times encrypt, then decrypt all onetime.
	randSlice(sample2, ec.XORKeyStream)
	dc.XORKeyStream(sample2, sample2)

	// assertion
	if dumpDiff(origin2, sample2) {
		t.Fatalf("Incorrect result")
	}

	// encrypt all onetime. then n-times decrypt
	ec.XORKeyStream(sample2, sample2)
	randSlice(sample2, dc.XORKeyStream)

	// assertion
	if dumpDiff(origin2, sample2) {
		t.Fatalf("Incorrect result")
	}
}

func TestChaChaStreamCorrectness(t *testing.T) {
	ec, dc := initChaCha(20)
	origin2 := bytes.Repeat(origin, 100)
	sample2 := append([]byte(nil), origin2...)

	for i := 0; i < 1e3; i++ {
		test_correctness(t, ec, dc, sample2, origin2)
	}
}

func dumpDiff(a, b []byte) bool {
	if string(a) == string(b) {
		return false
	}
	var j = -1
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			j = i
			break
		}
	}
	j1 := j - 32
	if j1 < 0 {
		j1 = 0
	}
	j2 := j + 32
	if j2 > len(a) {
		j2 = len(a)
	}
	dumpHex(a[j1:j2], "origin")
	dumpHex(b[j1:j2], "result")
	return true
}

func dumpHex(data []byte, label string) {
	fmt.Fprintln(os.Stdout, "------ dump ------", label)
	fmt.Fprintln(os.Stdout, hex.Dump(data))
}

func randSlice(sample []byte, call func(a, b []byte)) {
	mrand.Seed(int64(time.Now().Nanosecond()))

	for i := 0; i < len(sample); {
		rem := len(sample) - i
		s := mrand.Int() % rem
		if s == 0 {
			s = rem
		}
		smp := sample[i : i+s]
		call(smp, smp)
		i += s
	}
}
