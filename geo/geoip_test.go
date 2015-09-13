package geo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

const (
	count = 1 << 8
	loops = 1e5
)

var (
	geo       *GeoIP
	ipSamples [][]byte
)

func Test_init(t *testing.T) {
	runtime.GC()
	ms1, ms2 := new(runtime.MemStats), new(runtime.MemStats)
	t1 := time.Now().UnixNano()
	runtime.ReadMemStats(ms1)
	//---------------
	var err error
	geo, err = New()
	if err != nil {
		fmt.Println(err)
	}
	//----------------------
	t2 := time.Now().UnixNano()
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(ms2)
	t.Logf("time use=%.4fms", float64(t2-t1)/float64(1e6))
	t.Logf("mem Alloc.delta=%dk HeapInuse.delta=%dk",
		(ms2.Alloc-ms1.Alloc)/1024,
		(ms2.HeapInuse-ms1.HeapInuse)/1024)
}

func Test_order(t *testing.T) {
	var last1, last2 uint16
	for i, l1 := range geo.v4Ranges {
		for j, l2 := range l1 {
			for k := 0; k < len(l2); k += 6 {
				ui := binary.BigEndian.Uint32(l2[k : k+4])
				u1, u2 := uint16(ui>>16), uint16(ui)
				if last1 <= u1 {
					last1 = u1
				} else {
					t.Fatalf("unsorted %d<%d ? pos[%d, %d, %d]", last1, u1, i, j, k)
				}
				if last2 <= u2 {
					last2 = u2
				} else {
					t.Fatalf("unsorted %d<%d ? pos[%d, %d, %d]", last2, u2, i, j, k)
				}
				/*
					if u1 >= u2 {
						t.Fatalf("range %d<%d ? pos[%d, %d, %d]", u1, u2, i, j, k)
					}
				*/
			}
			last1, last2 = 0, 0
		}
	}
}

func Test_especial(t *testing.T) {
	samples := [][]interface{}{
		// "138.15.0.0","138.18.255.255" US
		{net.IPv4(138, 17, 0, 0), "US"},
		// "37.59.254.0","37.59.254.3","624688640","624688643","ES","Spain"
		{net.IPv4(37, 59, 254, 3), "ES"},
		// "37.59.254.4","37.59.254.51","624688644","624688691","FR","France"
		{net.IPv4(37, 59, 254, 4), "FR"},
		// "223.255.255.0","223.255.255.255","3758096128","3758096383","AU","Australia"
		{net.IPv4(223, 255, 255, 255), "AU"},
		// "1.34.0.0","1.34.0.0","19005440","19005440","CN","China"
		{net.IPv4(1, 34, 0, 0), "CN"},
	}
	for _, a := range samples {
		ip, c := a[0].(net.IP), a[1].(string)
		if v := geo.Lookup(ip[12:]); v != c {
			t.Fatalf("%s expected=%s but=%s", ip, c, v)
		}
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
		}
	}
	t2 := time.Now().UnixNano()
	all, totalTime := int64(loops*count), (t2-t1)/1e6
	t.Logf("querys=%d totalTime=%dms speed=%.2f per ms \n", all, totalTime, float64(all)/float64(totalTime))
}
