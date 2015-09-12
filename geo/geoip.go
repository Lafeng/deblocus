// secondary development in the underlying https://github.com/alecthomas/geoip
package geo

import (
	"bytes"
	"io/ioutil"
	"sort"
	"unsafe"
)

const (
	NA = "N/A"
)

type IPv4Range struct {
	start, end [4]byte
	country    [2]byte // ISO 3166-1 short country code.
}

type GeoIP struct {
	v4Ranges []*IPv4Range
	//countries map[string]*Country
}

func New() (*GeoIP, error) {
	r, err := DbBundle.Open("ranges.db")
	if err != nil {
		return nil, err
	}
	rb, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	rangesn := len(rb) / 10
	ranges := make([]*IPv4Range, rangesn)

	for i := 0; i < rangesn; i++ {
		ranges[i] = (*IPv4Range)(unsafe.Pointer(&rb[i*10]))
	}

	// Load countries
	/*
		c, err := db.DbBundle.Open("countries.csv")
		if err != nil {
			return nil, err
		}
		countries := map[string]*Country{}
		cc := csv.NewReader(c)
		for {
			row, err := cc.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			countries[row[0]] = &Country{Short: row[0], Long: row[1]}
		}
	*/

	return &GeoIP{
		//countries: countries,
		v4Ranges: ranges,
	}, nil
}

// Find country of IP.
func (g *GeoIP) Lookup(bip []byte) string {
	i := sort.Search(len(g.v4Ranges), func(i int) bool {
		return bytes.Compare(g.v4Ranges[i].start[:], bip) > 0
	})
	if i > 0 {
		i--
	}
	r := g.v4Ranges[i]
	if bytes.Compare(bip, r.start[:]) >= 0 && bytes.Compare(bip, r.end[:]) <= 0 {
		return string(r.country[:])
	}
	return NA
}
