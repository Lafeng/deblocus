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
	"unsafe"
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

func (r *GeoLite2Reader) ReadEntries() (entries entrySet, e error) {
	entries = make(entrySet, 0, 0xffff*3)
	var lineReader = func(fields []string) {
		// fields: cidr, id, ...
		ip, mask := ParseCIDR(fields[0])
		id, _ := strconv.Atoi(fields[1])
		code := r.CountryCode[id]
		if len(code) == 2 {
			entries = append(entries, &entry{data: ip, len: uint8(mask), nexthop: StoU16(code)})
		}
	}
	e = r.Iter(lineReader)
	return
}

func (r *GeoLite2Reader) ReadToRoutingTable() *routingTable {
	entries, e := r.ReadEntries()
	if e != nil {
		panic(e)
	}
	return buildRoutingTable(entries)
}

type GeoIPFilter struct {
	tab     *routingTable
	keyword string
}

func NewGeoIPFilter(keyword string) (f *GeoIPFilter, e error) {
	if len(keyword) != 2 {
		return nil, fmt.Errorf("filter keyword must be 2-byte country_iso_code")
	}
	f = new(GeoIPFilter)
	f.keyword = strings.ToUpper(keyword)
	f.tab = Deserialize(buildGeoDB())
	if log.V(1) {
		log.Infoln("Init GeoIPFilter with target keyword", keyword)
	}
	return
}

func (f *GeoIPFilter) Filter(host string) bool {
	ipAddr, e := net.ResolveTCPAddr("tcp4", host)
	if e != nil {
		return false
	}

	// net.IP is 16-byte, ipv4.addr at 12-15
	ip := binary.BigEndian.Uint32(ipAddr.IP[12:])
	if nexthop, y := f.tab.Find(ip); y {
		return U16toS(nexthop) == f.keyword
	}
	return false
}

type slice struct {
	array uintptr
	len   int
	cap   int
}

// Serialize routingTable{trie,base,pre} to 3-[]byte directly without copying
// then could make persistent data
func Serialize(r *routingTable) (t, b, p []byte) {
	tcnt, bcnt, pcnt := len(r.trie), len(r.base), len(r.pre)
	bsize, psize := unsafe.Sizeof(base_t{}), unsafe.Sizeof(pre_t{})
	t = convertToByteSlice(unsafe.Pointer(&r.trie), tcnt*4)
	b = convertToByteSlice(unsafe.Pointer(&r.base), bcnt*int(bsize))
	p = convertToByteSlice(unsafe.Pointer(&r.pre), pcnt*int(psize))
	return
}

// Recover []byte to compact struct instance directly without copying
// Time is money, yeah!
// Memory is money, yeah!
func Deserialize(t, b, p []byte) *routingTable {
	tcnt, bcnt, pcnt := len(t), len(b), len(p)
	bsize, psize := unsafe.Sizeof(base_t{}), unsafe.Sizeof(pre_t{})
	verifyLen(tcnt, 4)
	verifyLen(bcnt, bsize)
	verifyLen(pcnt, psize)
	return &routingTable{
		trie: *(*[]uint32)(convertToUnsafePointer(t, tcnt/4)),
		base: *(*[]base_t)(convertToUnsafePointer(b, bcnt/int(bsize))),
		pre:  *(*[]pre_t)(convertToUnsafePointer(p, pcnt/int(psize))),
	}
}

func verifyLen(total int, unitLen uintptr) {
	if total%int(unitLen) != 0 {
		panic(fmt.Errorf("total.len=%d was not divisible by unit=%d", total, unitLen))
	}
}

func convertToByteSlice(p unsafe.Pointer, _len int) []byte {
	slicePtr := (*slice)(p)
	newSlice := slice{slicePtr.array, _len, _len}
	return *(*[]byte)(unsafe.Pointer(&newSlice))
}

func convertToUnsafePointer(b []byte, _len int) unsafe.Pointer {
	slicePtr := (*slice)(unsafe.Pointer(&b))
	newSlice := slice{slicePtr.array, _len, _len}
	return unsafe.Pointer(&newSlice)
}

func AtoU16(a []byte) uint16 {
	return uint16(a[1]) | uint16(a[0])<<8
}

func StoU16(a string) uint16 {
	return uint16(a[1]) | uint16(a[0])<<8
}

func U16toS(u uint16) string {
	var buf = make([]byte, 2)
	buf[0] = uint8(u >> 8)
	buf[1] = uint8(u)
	return string(buf)
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

func RangeCIDR(s string) (uint32, uint32) {
	ip_start, m := ParseCIDR(s)
	ip_start = ip_start >> (32 - m) << (32 - m)
	ip_end := ip_start | (MASK32 >> m)
	return ip_start, ip_end
}

func IPv4Itoa(ip uint32) string {
	i, b := uint64(ip), 10
	return strconv.FormatUint(i>>24, b) + "." +
		strconv.FormatUint(i>>16&0xff, b) + "." +
		strconv.FormatUint(i>>8&0xff, b) + "." +
		strconv.FormatUint(i&0xff, b)
}
