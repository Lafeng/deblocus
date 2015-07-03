package tunnel

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestD5Code(t *testing.T) {
	buf := make([]byte, 2<<9)
	io.ReadFull(rand.Reader, buf)
	for i := 0; i < len(buf); i += 2 {
		buf[i+1] = d5Sub(buf[i])
	}
	for i := 0; i < len(buf); i += 2 {
		if !d5SumValid(buf[i], buf[i+1]) {
			t.Errorf("i=%d prev=%x next=%x\n", i, buf[i], buf[i+1])
		}
	}
}
