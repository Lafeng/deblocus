package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

func initChaCha() (*ChaCha, *ChaCha) {
	key := make([]byte, 32)
	iv := make([]byte, 8)
	io.ReadFull(rand.Reader, key)
	io.ReadFull(rand.Reader, iv)
	chacha20_1, _ := NewChaCha20(key, iv)
	chacha20_2, _ := NewChaCha20(key, iv)
	return chacha20_1, chacha20_2
}

func TestChaCha20Performance(t *testing.T) {
	ec, dc := initChaCha()
	count := int(1e5)
	sample := bytes.Repeat([]byte("abcdefghijklmnopqrstovwxyz1234567890"), 300)
	origin := append([]byte(nil), sample...)

	t1 := time.Now()
	for i := 0; i < count; i++ {
		ec.XORKeyStream(sample, sample)
		//dumpHex(ec.state[40:48], "iv")
	}

	tu := time.Now().Sub(t1).Nanoseconds() / 1e3
	t.Logf("ENC used=%dms speed=%.2fµs/per", tu/1e3, float32(tu)/float32(count))
	dumpHex(sample[:len(sample)%64], "enc")

	t1 = time.Now()
	for i := 0; i < count; i++ {
		dc.XORKeyStream(sample, sample)
		//dumpHex(dc.state[40:48], "iv")
	}

	tu = time.Now().Sub(t1).Nanoseconds() / 1e3
	t.Logf("DEC used=%dms speed=%.2fµs/per", tu/1e3, float32(tu)/float32(count))
	dumpHex(sample[:len(sample)%64], "dec")

	if bytes.Equal(origin, sample) {
		t.Logf("Correct sample.len=%d", len(sample))
	} else {
		t.Logf("result: % x", sample)
		t.Logf("origin: % x", origin)
		t.Fatalf("Incorrect result")
	}
}

func dumpHex(data []byte, label string) {
	fmt.Fprintln(os.Stdout, "------ dump ------", label)
	fmt.Fprintln(os.Stdout, hex.Dump(data))
}
