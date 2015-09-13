// forked from https://github.com/alecthomas/geoip
// And improved with 2-level 256-way + 16bits binary search
package geo

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	NA = "N/A"
)

type rawRecord struct {
	h16  uint16
	data []byte
}

type GeoIP struct {
	v4Ranges [][][]byte
}

func New() (*GeoIP, error) {
	g := new(GeoIP)
	ch := make(chan *rawRecord)
	go readRaw(ch)
	ranges_3d := make([][][]byte, 256)
	var rr, tmprr *rawRecord

outer:
	for i := 0; i < 256; {
		l1 := make([][]byte, 256)
		ranges_3d[i] = l1
		for {
			if tmprr != nil {
				rr, tmprr = tmprr, nil
			} else {
				rr = <-ch
				if rr.h16 == 0xff && rr.data == nil {
					break outer
				}
			}
			f8, s8 := int(rr.h16>>8), int(rr.h16&0xff)
			if f8 == i {
				if l1[s8] != nil {
					fmt.Printf("old %#v\n", l1[s8])
					fmt.Printf("new %#v\n", rr.data)
					panic(fmt.Errorf("f8 s8 = %d %d", f8, s8))
				}
				l1[s8] = rr.data
			} else {
				tmprr, i = rr, f8
				break
			}
		}
	}

	g.v4Ranges = ranges_3d
	return g, nil
}

func readRaw(ch chan *rawRecord) {
	var raw []byte = buildGeoDB()
	rawLen := len(raw)
	for i := 4; i < rawLen; {
		label := raw[i-4 : i]
		blen, h16 := int(binary.BigEndian.Uint16(label)), binary.BigEndian.Uint16(label[2:])
		ch <- &rawRecord{h16, raw[i : i+blen]}
		i += blen + 4
	}
	ch <- &rawRecord{0xff, nil}
}

// Find country of IP.
func (g *GeoIP) Lookup(bip []byte) string {
	if subRanges := g.v4Ranges[bip[0]]; subRanges != nil {
		if ranges := subRanges[bip[1]]; ranges != nil {
			bip = bip[2:]
			var j int
			if i := binSearch(ranges, bip); i > 0 {
				j = (i - 1) * 6
			}
			r := ranges[j : j+6]
			if bytes.Compare(bip, r[:2]) >= 0 && bytes.Compare(bip, r[2:4]) <= 0 {
				return string(r[4:6])
			}
		}
	}
	return NA
}

func binSearch(ranges, bip []byte) int {
	// Define f(-1) == false and f(n) == true.
	// Invariant: f(i-1) == false, f(j) == true.
	i, j := 0, len(ranges)/6
	for i < j {
		h := i + (j-i)/2 // avoid overflow when computing h
		// i ≤ h < j
		if off := h * 6; bytes.Compare(ranges[off:off+2], bip) <= 0 {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	return i
}
