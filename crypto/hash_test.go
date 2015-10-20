package crypto

import (
	"hash/crc32"
	"hash/fnv"
	"testing"
)

func initSample(n int) ([]byte, int64) {
	return make([]byte, n), int64(n)
}

func Benchmark_crc32_6(b *testing.B) {
	buf, n := initSample(6)
	tab := crc32.MakeTable(crc32.Castagnoli)
	b.SetBytes(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crc32.Checksum(buf, tab)
	}
}

func Benchmark_fnv_6(b *testing.B) {
	buf, n := initSample(6)
	f := fnv.New32a()
	b.SetBytes(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Write(buf)
	}
}

func Benchmark_fnv6_6(b *testing.B) {
	buf, n := initSample(6)
	b.SetBytes(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash16Of6(buf)
	}
}
