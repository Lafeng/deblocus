package tunnel

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestD5Code(t *testing.T) {
	buf := make([]byte, 100)
	io.ReadFull(rand.Reader, buf)
	for i := 0; i < len(buf); i += 2 {
		buf[i+1] = byte(D5 - int(int8(buf[i])))
	}
	for i := 0; i < len(buf); i += 2 {
		sum := uint(int8(buf[i])+int8(buf[i+1])) & 0xff
		if sum != D5 {
			t.Errorf("i=%d prev=%x next=%x sum=%d\n", i, buf[i], buf[i+1], sum)
		}
	}
}
