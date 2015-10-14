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
	b = (b + 63) >> 6 << 6
	sample = bytes.Repeat([]byte("abcdefghijklmnopqrstovwxyz1234567890"), ((b+35)/36)*36)[:b]
	origin = append([]byte(nil), sample...)
	test_cpu_internal()
	fmt.Fprintf(os.Stderr, "Testing with sample.length=%d\n", len(sample))
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
		fmt.Fprintf(os.Stderr, "CPU "+format+"\n", args...)
	}
	code := dump_cpu_features()
	features := make([]string, 0, 32)
	if len(code) <= 0 {
		goto capability
	}
	for j, v := range _features_table {
		i, bit := v[1].(int), uint(v[2].(int))
		if code[3-i]&(1<<bit) > 0 {
			features = append(features, v[0].(string))
		}
		if (len(features)+1)%0xb == 0 || j+1 == len(_features_table) {
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

var _features_table = [][]interface{}{
	{"fpu", 3, 0},
	{"vme", 3, 1},
	{"de", 3, 2},
	{"pse", 3, 3},
	{"tsc", 3, 4},
	{"msr", 3, 5},
	{"pae", 3, 6},
	{"mce", 3, 7},
	{"cx8", 3, 8},
	{"apic", 3, 9},
	{"sep", 3, 11},
	{"mtrr", 3, 12},
	{"pge", 3, 13},
	{"mca", 3, 14},
	{"cmov", 3, 15},
	{"pat", 3, 16},
	{"pse-36", 3, 17},
	{"psn", 3, 18},
	{"clflsh", 3, 19},
	{"ds", 3, 21},
	{"acpi", 3, 22},
	{"mmx", 3, 23},
	{"fxsr", 3, 24},
	{"sse", 3, 25},
	{"sse2", 3, 26},
	{"ss", 3, 27},
	{"htt", 3, 28},
	{"tm", 3, 29},
	{"pbe", 3, 31},
	{"sse3", 2, 0},
	{"pclmuldq", 2, 1},
	{"dtes64", 2, 2},
	{"monitor", 2, 3},
	{"ds-cpl", 2, 4},
	{"vmx", 2, 5},
	{"smx", 2, 6},
	{"est", 2, 7},
	{"tm2", 2, 8},
	{"ssse3", 2, 9},
	{"cnxt-id", 2, 10},
	{"cx16", 2, 13},
	{"xtpr", 2, 14},
	{"pdcm", 2, 15},
	{"dca", 2, 18},
	{"sse4.1", 2, 19},
	{"sse4.2", 2, 20},
	{"x2apic", 2, 21},
	{"movbe", 2, 22},
	{"popcnt", 2, 23},
	{"aes", 2, 25},
	{"xsave", 2, 26},
	{"osxsave", 2, 27},
	{"avx", 2, 28},
	{"f16c", 2, 29},
	{"rdrnd", 2, 30},
	{"hypervisor", 2, 31},
	{"fsgsbase", 1, 0},
	{"bmi1", 1, 3},
	{"hle", 1, 4},
	{"avx2", 1, 5},
	{"smep", 1, 7},
	{"bmi2", 1, 8},
	{"erms", 1, 9},
	{"invpcid", 1, 10},
	{"rtm", 1, 11},
	{"mpx", 1, 14},
	{"avx512f", 1, 16},
	{"avx512f", 1, 16},
	{"avx512dq", 1, 17},
	{"rdseed", 1, 18},
	{"adx", 1, 19},
	{"smap", 1, 20},
	{"avx512ifma", 1, 21},
	{"pcommit", 1, 22},
	{"clflushopt", 1, 23},
	{"clwb", 1, 24},
	{"avx512pf", 1, 26},
	{"avx512er", 1, 27},
	{"avx512cd", 1, 28},
	{"sha", 1, 29},
	{"avx512bw", 1, 30},
	{"avx512vl", 1, 31},
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
