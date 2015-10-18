package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"strings"
	"testing"
	"time"
)

var sample, origin []byte

func initAddonArgs(defVal int) int {
	var v int
	flag.IntVar(&v, "bytes", defVal, "bytes per round")
	flag.Parse()
	return v
}

func init() {
	b := initAddonArgs(320 * 36)
	//b = (b + 63) >> 6 << 6
	sample = bytes.Repeat([]byte("abcdefghijklmnopqrstovwxyz1234567890"), ((b+35)/36)*36)[:b]
	origin = append([]byte(nil), sample...)
	test_cpu_internal()
	fmt.Fprintf(os.Stderr, "Testing block.length=%d\n", len(sample))
}

func new_ChaCha(rounds uint) (cipher.Stream, cipher.Stream) {
	key := make([]byte, 40)
	io.ReadFull(rand.Reader, key)
	chacha_1, _ := NewChaCha(key[:32], key[32:], rounds)
	chacha_2, _ := NewChaCha(key[:32], key[32:], rounds)
	return chacha_1, chacha_2
}

func new_aes(bitlen int, mode BLOCK_MODE) (cipher.Stream, cipher.Stream) {
	key := make([]byte, bitlen>>3)
	io.ReadFull(rand.Reader, key)
	aes, _ := NewAESCipher(key, mode)
	ec, _ := NewAESEncrypter(aes, key)
	dc, _ := NewAESDecrypter(aes, key)
	return ec, dc
}

func new_aes_gcm(bitlen int) (cipher.AEAD, cipher.AEAD, []byte) {
	key := make([]byte, bitlen>>3)
	ec, _ := NewAES_GCM(key)
	dc, _ := NewAES_GCM(key)
	return ec, dc, key[:ec.NonceSize()]
}

func Benchmark_ChaCha8_xor(b *testing.B) {
	ec, _ := new_ChaCha(8)
	b.SetBytes(int64(len(sample)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_ChaCha12_xor(b *testing.B) {
	ec, _ := new_ChaCha(12)
	b.SetBytes(int64(len(sample)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_ChaCha20_xor(b *testing.B) {
	ec, _ := new_ChaCha(20)
	b.SetBytes(int64(len(sample)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES128_ctr(b *testing.B) {
	b.SetBytes(int64(len(sample)))
	ec, _ := new_aes(128, MODE_CTR)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES192_ctr(b *testing.B) {
	b.SetBytes(int64(len(sample)))
	ec, _ := new_aes(192, MODE_CTR)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES256_ctr(b *testing.B) {
	b.SetBytes(int64(len(sample)))
	ec, _ := new_aes(256, MODE_CTR)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES128_ofb(b *testing.B) {
	b.SetBytes(int64(len(sample)))
	ec, _ := new_aes(128, MODE_OFB)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES256_ofb(b *testing.B) {
	b.SetBytes(int64(len(sample)))
	ec, _ := new_aes(256, MODE_OFB)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.XORKeyStream(sample, sample)
	}
}

func Benchmark_AES128_gcm(b *testing.B) {
	out := make([]byte, len(sample)+16)
	ec, _, iv := new_aes_gcm(128)

	b.SetBytes(int64(len(sample)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.Seal(out, iv, sample, nil)
	}
}

func Benchmark_AES256_gcm(b *testing.B) {
	out := make([]byte, len(sample)+16)
	ec, _, iv := new_aes_gcm(256)

	b.SetBytes(int64(len(sample)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ec.Seal(out, iv, sample, nil)
	}
}

func test_cpu_internal() {
	var msg = func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, "> CPU "+format+"\n", args...)
	}
	code := get_cpuid()
	features := make([]string, 0, 32)
	var features_table [][]interface{}
	switch len(code) {
	case 4:
		features_table = x86_features
	case 1:
		features_table = armv8_features
	default:
		goto capability
	}
	for j, v := range features_table {
		i, bit := v[1].(int), uint(v[2].(int))
		if code[i]&(1<<bit) > 0 {
			features = append(features, v[0].(string))
		}
		if (len(features)+1)%0xb == 0 || j+1 == len(features_table) {
			msg("features:  %s", strings.Join(features, " "))
			features = features[:0]
		}
	}

capability:
	msg("AES-hardware=%d NEON-capable=%d", has_aes_hardware(), is_NEON_capable())
}

func Test_ChaCha_Stream(t *testing.T) {
	ec, dc := new_ChaCha(20)
	origin2 := bytes.Repeat(origin, 10)
	sample2 := append([]byte(nil), origin2...)

	for i := 0; i < 1e3; i++ {
		test_correctness(t, ec, dc, sample2, origin2)
	}
	n2 := min(len(sample2), 0xfff)
	test_correctness2(t, ec, dc, sample2[:n2], origin2[:n2])
}

func Test_AES_Stream(t *testing.T) {
	ec, dc := new_aes(128, MODE_CTR)
	origin2 := bytes.Repeat(origin, 10)
	sample2 := append([]byte(nil), origin2...)

	for i := 0; i < 1e3; i++ {
		test_correctness(t, ec, dc, sample2, origin2)
	}
	test_correctness2(t, ec, dc, sample2, origin2)
}

func Test_ChaCha_Standard(t *testing.T) {
	for _, vec := range chacha_test_vectors {
		chacha_std_test(t, vec[0], vec[1], vec[2])
	}
}

func chacha_std_test(t *testing.T, _key, _iv, _expected string) {
	var key, iv, in, out, expected []byte
	in = make([]byte, 64) // zero xor
	out = make([]byte, len(in))

	key = decode_hex(_key)
	iv = decode_hex(_iv)
	c, e := NewChaCha(key, iv, 20)
	if e != nil {
		t.Fatal(e)
	}
	c.XORKeyStream(out, in)
	expected = decode_hex(_expected)
	if dumpDiff(expected, out) {
		t.Fatalf("Incorrect result")
	}
}

func decode_hex(s string) []byte {
	code, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	if len(code) != len(s)/2 {
		panic("decode error")
	}
	return code
}

func Test_AES_GCM(t *testing.T) {
	plain := append([]byte(nil), origin...)
	out1 := make([]byte, len(plain)+16)
	out2 := make([]byte, len(out1))

	ec, dc, iv := new_aes_gcm(128)
	out1 = ec.Seal(out1, iv, plain, nil)

	out2, err := dc.Open(out2, iv, out1, nil)
	// assertion
	if dumpDiff(plain, out2) {
		t.Logf("plain=%d Seal=%d Open=%d", len(plain), len(out1), len(out2))
		t.Fatalf("Incorrect result %v", err)
	}
}

func test_correctness(t *testing.T, ec, dc cipher.Stream, sample2, origin2 []byte) {
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

func test_correctness2(t *testing.T, ec, dc cipher.Stream, sample2, origin2 []byte) {
	n := mrand.Int() & 0xff
	for i := 0; i < n; i++ {
		ec.XORKeyStream(sample2, sample2)
	}
	for i := 0; i < n; i++ {
		dc.XORKeyStream(sample2, sample2)
	}
	// assertion
	if dumpDiff(origin2, sample2) {
		t.Fatalf("Incorrect result")
	}
}

func dumpDiff(a, b []byte) bool {
	if string(a) == string(b) {
		return false
	}
	var j = -1
	for i := 0; i < min(len(a), len(b)); i++ {
		if a[i] != b[i] {
			j = i
			break
		}
	}
	j1 := max(j-32, 0)
	j2 := j + 32
	dumpHex(a[j1:min(j2, len(a))], fmt.Sprintf("origin :0x%x/0x%x", j1, len(a)))
	dumpHex(b[j1:min(j2, len(b))], fmt.Sprintf("result :0x%x/0x%x", j1, len(b)))
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func max(a, b int) int {
	if a < b {
		return b
	} else {
		return a
	}
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
