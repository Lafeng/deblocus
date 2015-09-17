package geo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"unsafe"
	//"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	samplesSize = 1 << 9
	loopCount   = 1e5
)

var tab *routingTable

var nets = []string{
	"1.1.1.0/24",
	"1.1.2.0/24",
	"1.1.2.4/29",
	"1.1.2.8/30",
	"1.1.3.0/24",
	"1.1.4.4/30",
}

// Begin testing of manual samples
func Test_buildFromString(t *testing.T) {
	var entries = make(entrySet, len(nets))
	for i, v := range nets {
		ip, mask := ParseCIDR(v)
		ip = ip >> (32 - mask) << (32 - mask)
		entries[i] = &entry{data: ip, len: uint8(mask), nexthop: uint16(i)}
		//		if true {
		if false {
			fmt.Printf("%d %d %d\n", ip, mask, i)
		}
	}
	t1 := time.Now()
	tab = buildRoutingTable(entries)
	tu := time.Since(t1).Nanoseconds() / 1e6
	t.Logf("build table size=%d use=%dms", len(nets), tu)
}

func Test_manual_query(t *testing.T) {
	samples := `
	1.1.1.1
	1.1.2.3
	1.1.2.255
	1.1.2.4
	1.1.2.6
	1.1.2.7
	1.1.3.3
	1.1.4.4
	1.1.4.255
	`
	for _, l := range strings.Fields(samples) {
		ip, _ := ParseCIDR(l + "/")
		p, y := tab.Find(ip)
		if !y {
			t.Logf("routing for %s not found", l)
			continue
		}
		b, e := RangeCIDR(nets[p])
		if ip >= b && ip <= e {
			t.Logf("found %15s by %s[%s, %s]", l, U16toS(p), IPv4Itoa(b), IPv4Itoa(e))
		} else {
			t.Logf("found %15s by %s[%s, %s]", l, U16toS(p), IPv4Itoa(b), IPv4Itoa(e))
		}
	}
}

// Begin testing of random samples
// routing table from file
func Test_buildFromFile(t *testing.T) {
	tab = nil
	reader := new(GeoLite2Reader)
	reader.RelativePath = "../static/"
	entries, e := reader.ReadEntries()
	if e != nil {
		t.Fatal(e)
	}
	reader = nil
	var ms1, ms2 = new(runtime.MemStats), new(runtime.MemStats)
	runtime.GC()
	runtime.ReadMemStats(ms1)
	tab = buildRoutingTable(entries)
	runtime.GC()
	runtime.ReadMemStats(ms2)
	t.Logf("tab trie=%d base=%d pre=%d", len(tab.trie), len(tab.base), len(tab.pre))
	t.Logf("mem HeapAlloc=%dk HeapInuse=%dk HeapIdle=%dk HeapSys=%dk",
		(int64(ms2.HeapAlloc)-int64(ms1.HeapAlloc))/1024,
		(int64(ms2.HeapInuse)-int64(ms1.HeapInuse))/1024,
		(int64(ms2.HeapIdle)-int64(ms1.HeapIdle))/1024,
		(int64(ms2.HeapSys)-int64(ms1.HeapSys))/1024,
	)
}

func Test_query_performance(t *testing.T) {
	samples := generateSamples()
	var i, j int
	t1 := time.Now()
	for i = 0; i < loopCount; i++ {
		for j = 0; j < samplesSize; j++ {
			tab.Find(samples[j])
		}
	}
	tu := time.Since(t1).Nanoseconds()
	all, totalTime := int64(i*j), tu/1e6
	t.Logf("querys=%d totalTime=%dms speed=%.2f per ms \n", all, totalTime, float64(all)/float64(totalTime))
}

func generateSamples() []uint32 {
	samplesRaw := make([]byte, 4*samplesSize)
	io.ReadFull(rand.Reader, samplesRaw)
	samples := make([]uint32, samplesSize)
	for i := 0; i < samplesSize; i++ {
		samples[i] = binary.BigEndian.Uint32(samplesRaw[i*4 : i*4+4])
	}
	return samples
}

type referrence struct {
	start, end []uint32
	country    []string
	size       int
}

func Test_correctness(t *testing.T) {
	_t, b, p := Serialize(tab)
	tab = Deserialize(_t, b, p)
	var ref = _buildReferrence(t)
	var i, j int
	for i = 0; i < loopCount>>2; i++ {
		samples := generateSamples()
		for j = 0; j < samplesSize; j++ {
			var found1, found2 string
			ip := samples[j]
			// from lc-trie
			if fd1, y := tab.Find(ip); y {
				found1 = U16toS(fd1)
			}
			// from binary search
			index := sort.Search(ref.size, func(k int) bool {
				return ref.start[k] > ip
			})
			if index > 0 {
				index--
			}
			if ref.start[index] <= ip && ref.end[index] >= ip {
				found2 = ref.country[index]
			}
			if found1 != found2 {
				t.Fatalf("INCORRECT --- ip=%s found1=%s found2=%s", IPv4Itoa(ip), found1, found2)
			}
		}
	}
	t.Logf("Correctness testing count=%d", i*j)
}

func Test_alignment(t *testing.T) {
	var e entry
	var b base_t
	var p pre_t
	t.Logf("sizeof entry=%d base_t=%d pre_t=%d", unsafe.Sizeof(e), unsafe.Sizeof(b), unsafe.Sizeof(p))
}

func _buildReferrence(t *testing.T) *referrence {
	var (
		start   = make([]uint32, 0, 0xffff)
		end     = make([]uint32, 0, 0xffff)
		country = make([]string, 0, 0xffff)
	)
	reader := new(GeoLite2Reader)
	reader.RelativePath = "../static/"
	var i = 0
	var lineReader = func(fields []string) {
		id, _ := strconv.Atoi(fields[1])
		code := reader.CountryCode[id]
		s, e := RangeCIDR(fields[0])
		if len(code) == 2 {
			i++
			start = append(start, s)
			end = append(end, e)
			country = append(country, code)
		}
	}
	if e := reader.Iter(lineReader); e != nil {
		t.Fatal(e)
	}
	return &referrence{start, end, country, i}
}
