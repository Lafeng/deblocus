package geo

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	log "github.com/Lafeng/deblocus/golang/glog"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	GEO2_LOC_FILE  = "GeoLite2-Country-Locations-en.csv"
	GEO2_IPV4_FILE = "GeoLite2-Country-Blocks-IPv4.csv"
)

type GeoLite2Reader struct {
	ipv4fp       *os.File
	locfp        *os.File
	CountryCode  map[int]string
	Count        int
	RelativePath string
}

func (r *GeoLite2Reader) Iter(callback func(fields []string)) (e error) {
	r.locfp, e = os.Open(r.RelativePath + GEO2_LOC_FILE)
	if e != nil {
		return e
	}
	defer r.locfp.Close()
	var countryCode = make(map[int]string)
	for rd := csv.NewReader(r.locfp); ; {
		row, e := rd.Read()
		if e != nil {
			break
		}
		id, _ := strconv.Atoi(row[0]) // geoname_id
		if _, y := countryCode[id]; !y {
			countryCode[id] = row[4] // country_iso_code
		}
	}
	r.CountryCode = countryCode
	r.ipv4fp, e = os.Open(r.RelativePath + GEO2_IPV4_FILE)
	if e != nil {
		return e
	}
	defer r.ipv4fp.Close()
	rd := csv.NewReader(r.ipv4fp)
	rd.Read() // skip first line
	var (
		i      = 0
		fields []string
	)
	for ; ; i++ {
		fields, e = rd.Read()
		if e != nil || fields == nil {
			if e == io.EOF {
				e = nil
			}
			break
		}
		callback(fields)
	}
	r.Count = i
	return
}

type GeoIPFilter struct {
	tab     *routingTable
	keyword string
}

func NewGeoIPFilter(keyword string) (f *GeoIPFilter, e error) {
	if len(keyword) != 2 {
		return nil, fmt.Errorf("filter keyword must be 2-byte country_iso_code")
	}
	var db = buildGeoDB()
	var size = len(db) / 6
	entries := make(entrySet, size)
	for i := 0; i < size; i++ {
		j := i * 6
		entries[i] = &entry{
			data:    binary.BigEndian.Uint32(db[j : j+4]),
			len:     uint32(db[j+4]),
			nexthop: string(db[j+5 : j+6]),
		}
	}
	f = new(GeoLite2Reader)
	f.keyword = strings.ToUpper(keyword)
	f.tab = buildRoutingTable(entries)
	if log.V(1) {
		log.Infoln("Init GeoIPFilter with target keyword", keyword)
	}
	return
}

func (f *GeoIPFilter) Filter(host string) bool {
	ipAddr, e := net.ResolveIPAddr("ip4", host)
	if e != nil {
		return false
	}

	// net.IP is 16-byte, ipv4.addr at 12-15
	ip := binary.BigEndian.Uint32(ipAddr.IP[12:])
	if nexthop, y := f.tab.Find(ip); y {
		return nexthop == f.keyword
	}
	return false
}

/*
 CIDR utils
*/
// parse 10-bit cidr literal to binary ip/mask
func ParseCIDR(s string) (ip, m uint32) {
	for _, c := range []byte(s) {
		if d := c - 0x30; d >= 0 && d <= 9 { // number
			m = m*10 + uint32(d)
		} else if c == '.' || c == '/' {
			ip, m = (ip<<8)|m, 0
		} else if c == ' ' { // space
			continue
		} else { // exception
			return
		}
	}
	return
}

var mask32 uint32 = 0xffffffff

func RangeCIDR(s string) (uint32, uint32) {
	ip_start, m := ParseCIDR(s)
	ip_start = ip_start >> (32 - m) << (32 - m)
	ip_end := ip_start | (mask32 >> m)
	return ip_start, ip_end
}

func IPv4Itoa(ip uint32) string {
	i, b := uint64(ip), 10
	return strconv.FormatUint(i>>24, b) + "." +
		strconv.FormatUint(i>>16&0xff, b) + "." +
		strconv.FormatUint(i>>8&0xff, b) + "." +
		strconv.FormatUint(i&0xff, b)
}
