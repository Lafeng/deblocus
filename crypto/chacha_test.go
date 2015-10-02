package crypto

import (
	"bytes"
	//	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
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
	count := int(1e4)
	sample := bytes.Repeat([]byte("abcdefghijklmnopqrstovwxyz1234567890"), 500)
	origin := append([]byte(nil), sample...)

	t1 := time.Now()
	for i := 0; i < count; i++ {
		ec.XORKeyStream(sample, sample)
		//dumpHex(ec.state[40:48], "iv")
	}

	tu := time.Now().Sub(t1).Nanoseconds() / 1e3
	t.Logf("ENC used=%dms speed=%.2fµs/per throughput=%dM/s",
		tu/1e3, float32(tu)/float32(count), int64(count*len(sample))*1e6/(tu*(1<<20)))

	t1 = time.Now()
	for i := 0; i < count; i++ {
		dc.XORKeyStream(sample, sample)
		//dumpHex(dc.state[40:48], "iv")
	}

	tu = time.Now().Sub(t1).Nanoseconds() / 1e3
	t.Logf("DEC used=%dms speed=%.2fµs/per throughput=%dM/s",
		tu/1e3, float32(tu)/float32(count), int64(count*len(sample))*1e6/(tu*(1<<20)))

	if bytes.Equal(origin, sample) {
		t.Logf("OK count=%d sample.len=%d", count, len(sample))
	} else {
		t.Logf("result: % x", sample)
		t.Logf("origin: % x", origin)
		t.Fatalf("Incorrect result")
	}
}

func TestStream(t *testing.T) {
	ec, dc := initChaCha()
	sample := bytes.Repeat([]byte("abcdefghijklmnopqrstovwxyz1234567890"), 9)
	origin := append([]byte(nil), sample...)

	randChip("dec", sample, func(chip []byte) {
		ec.XORKeyStream(chip, chip)
	})

	dc.XORKeyStream(sample, sample)
	dumpHex(sample, "dec")

	if bytes.Equal(origin, sample) {
		t.Logf("Correct sample.len=%d", len(sample))
	} else {
		t.Logf("result: % x", sample)
		t.Logf("origin: % x", origin)
		t.Fatalf("Incorrect result")
	}

	ec.XORKeyStream(sample, sample)

	randChip("dec", sample, func(chip []byte) {
		dc.XORKeyStream(chip, chip)
	})

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
		dumpHex(smp, label+" chip")
		i += s
	}
}
