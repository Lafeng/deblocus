package geo

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

const (
	count = 1 << 9
	loops = 1e4
)

var (
	geo       *GeoIP
	ipSamples [][]byte
)

func init() {
	var err error
	geo, err = New()
	if err != nil {
		fmt.Println(err)
	}
}

func Test_random(t *testing.T) {
	samples := make([]byte, 4*count)
	io.ReadFull(rand.Reader, samples)
	ipSamples = make([][]byte, count)
	for i := 0; i < count; i++ {
		ipRaw := samples[i : i+4]
		ipSamples[i] = ipRaw
		a := net.IPv4(0, 0, 0, 0)
		copy(a[12:], ipRaw)
		t.Logf("query %s=%s", a, geo.Lookup(ipRaw))
	}
}

func Test_performance(t *testing.T) {
	t1 := time.Now().UnixNano()
	for i := 0; i < loops; i++ {
		for _, ip := range ipSamples {
			geo.Lookup(ip)
			/*if l := geo.Lookup(ip); l == "" {
				fmt.Println(ip, "not found")
			}*/
		}
	}
	t2 := time.Now().UnixNano()
	all, totalTime := int64(loops*count), (t2-t1)/1e6
	t.Logf("querys=%d totalTime=%dms speed=%.2f per ms \n", all, totalTime, float64(all)/float64(totalTime))
}
