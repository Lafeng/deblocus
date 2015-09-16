package geo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
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
		entries[i] = &entry{data: ip, len: mask, nexthop: v}
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
		b, e := RangeCIDR(p.(string))
		if ip >= b && ip <= e {
			t.Logf("found %15s by %s[%s, %s]", l, p, IPv4Itoa(b), IPv4Itoa(e))
		} else {
			t.Logf("found %15s by %s[%s, %s]", l, p, IPv4Itoa(b), IPv4Itoa(e))
		}
	}
}

var ref *referrence

type referrence struct {
	start, end, mask []uint32
	country          []string
	size             int
}

// Begin testing of random samples
// routing table from file
func Test_buildFromFile(t *testing.T) {
	var (
		entries = make(entrySet, 0, 0xffff)
		masks   = make([]uint32, 0, 0xffff)
		start   = make([]uint32, 0, 0xffff)
		end     = make([]uint32, 0, 0xffff)
		country = make([]string, 0, 0xffff)
	)
	reader := new(GeoLite2Reader)
	reader.RelativePath = "../static/"
	var lineReader = func(fields []string) {
		// fields: cidr, id, ...
		ip, mask := ParseCIDR(fields[0])
		id, _ := strconv.Atoi(fields[1])
		code := reader.CountryCode[id]
		entries = append(entries, &entry{data: ip, len: mask, nexthop: code})

		s, e := RangeCIDR(fields[0])
		masks = append(masks, mask)
		start = append(start, s)
		end = append(end, e)
		country = append(country, code)
	}
	if e := reader.Iter(lineReader); e != nil {
		t.Fatal(e)
	}
	t1 := time.Now()
	tab = buildRoutingTable(entries)
	tu := time.Since(t1).Nanoseconds() / 1e6
	t.Logf("build table size=%d use=%dms", reader.Count, tu)
	ref = &referrence{start, end, masks, country, reader.Count}
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

func Test_correctness(t *testing.T) {
	var i, j int
	for i = 0; i < loopCount>>1; i++ {
		samples := generateSamples()
		for j = 0; j < samplesSize; j++ {
			var found1, found2 string
			ip := samples[j]
			// from lc-trie
			if fd1, y := tab.Find(ip); y {
				found1 = fd1.(string)
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

func Test_memory(t *testing.T) {
	tab = nil
	entries := make(entrySet, ref.size)
	for i := 0; i < ref.size; i++ {
		entries[i] = &entry{data: ref.start[i], len: ref.mask[i], nexthop: ref.country[i]}
	}
	ref = nil
	runtime.GC()
	runtime.GC()
	var ms1, ms2 = new(runtime.MemStats), new(runtime.MemStats)
	runtime.ReadMemStats(ms1)
	tab = buildRoutingTable(entries)
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(ms2)
	t.Logf("tab trie=%d base=%d pre=%d", len(tab.trie), len(tab.base), len(tab.pre))
	t.Logf("mem Alloc.delta=%dk HeapInuse.delta=%dk",
		(ms2.Alloc-ms1.Alloc)/1024,
		(ms2.HeapInuse-ms1.HeapInuse)/1024)
}
