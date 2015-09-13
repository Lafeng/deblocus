package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	//	"io"
	"os"
	"strconv"
)

const (
	db_file   = "../geo/geodb.go"
	geo_file  = "GeoIPCountryWhois.csv"
	self_name = "update-geodb.go"
)

func throwIf(cond bool, e ...interface{}) {
	if cond {
		var err string
		if f, y := e[0].(string); y {
			err = fmt.Sprintf(f, e[1:]...)
		} else {
			err = fmt.Sprint(e...)
		}
		panic(err)
	}
}

func main() {
	if IsNotExist(self_name) {
		fmt.Println("Please change cwd to be same as", self_name)
		os.Exit(1)
	}
	p := new(parser)
	p.init()
	defer p.free()
	p.parse()
}

type parser struct {
	srcFile, dstFile *os.File
	dstEntryBuf      *bytes.Buffer
	dstEntry         *zlib.Writer
	h8Cnt            int
	lastH16          uint16
	latestLf         bool
}

func (p *parser) init() {
	var e error
	p.srcFile, e = os.Open(geo_file)
	throwIf(e != nil, "open %s %v", geo_file, e)
	p.dstFile, e = os.OpenFile(db_file, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666)
	throwIf(e != nil, "OpenFile %s %v", db_file, e)
	p.dstEntryBuf = new(bytes.Buffer)
	p.dstEntry = zlib.NewWriter(p.dstEntryBuf)
}

func (p *parser) free() {
	if p.srcFile != nil {
		p.srcFile.Close()
	}
	if p.dstFile != nil {
		p.dstFile.Close()
	}
}

func (p *parser) parse() {
	var (
		rr  = newRecordReader(p.srcFile)
		rw  = new(bytes.Buffer)
		buf = make([]byte, 6)
	)
	for rr.hasNext() {
		v := rr.get()
		var h16 uint16

		_start, _end := v.start, minUint32(v.start|0xffff, v.end)
		for _end <= v.end {
			h16 = uint16(_start >> 16)
			binary.BigEndian.PutUint16(buf, uint16(_start))
			binary.BigEndian.PutUint16(buf[2:], uint16(_end))
			copy(buf[4:], []byte(v.county))
			n, e := rw.Write(buf)
			throwIf(n != 6 || e != nil, "Write memory %v", e)

			_start = ((_start >> 16) + 1) << 16
			if _end&0xffff == 0xffff { // this range cross over net/16
				p.write16Segment(rw.Bytes(), h16)
				rw.Reset()
			}
			_end = _start + (_end & 0xffff)
		}
		if rr.next_h16_gt(h16) {
			p.write16Segment(rw.Bytes(), h16)
			rw.Reset()
		}
	}
	p.writeEnd()
}

func (p *parser) write16Segment(data []byte, h16 uint16) {
	if len(data) <= 0 {
		return
	}
	label := make([]byte, 4)
	binary.BigEndian.PutUint16(label, uint16(len(data)))
	binary.BigEndian.PutUint16(label[2:], h16)
	p.dstEntry.Write(label)
	p.dstEntry.Write(data)
}

func (p *parser) writeEnd() {
	// zlib flush, close
	p.dstEntry.Flush()
	p.dstEntry.Close()
	// bufed file
	dst := bufio.NewWriter(p.dstFile)
	dst.WriteString(header)
	dst.WriteString(strconv.QuoteToASCII(string(p.dstEntryBuf.Bytes())))
	dst.WriteString(footer)
	dst.Flush()
}

func IsNotExist(file string) bool {
	_, err := os.Stat(file)
	return os.IsNotExist(err)
}

func parseUint32(v string) uint32 {
	i, e := strconv.ParseUint(v, 10, 32)
	throwIf(e != nil, "ParseUint %s %v", v, e)
	return uint32(i)
}

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	} else {
		return b
	}
}

type record struct {
	start, end uint32
	county     string
}

type recordReader struct {
	f        *os.File
	rd       *csv.Reader
	tmp      *record
	markRead bool
}

func newRecordReader(f *os.File) *recordReader {
	return &recordReader{
		f:  f,
		rd: csv.NewReader(f),
	}
}

func (r *recordReader) hasNext() bool {
	if r.markRead {
		r.markRead = false
		return r.tmp != nil
	}
	fields, _ := r.rd.Read()
	if fields != nil {
		r.tmp = &record{
			start:  parseUint32(fields[2]),
			end:    parseUint32(fields[3]),
			county: fields[4],
		}
		return true
	}
	return false
}

func (r *recordReader) get() (rd *record) {
	rd = r.tmp
	r.tmp = nil
	r.hasNext()
	r.markRead = true
	return
}

func (r *recordReader) next_h16_gt(h16 uint16) bool {
	return r.tmp == nil || uint16(r.tmp.start>>16) > h16
}

var header = `package geo

import (
	"bytes"
	"compress/zlib"
	"io"
)

func buildGeoDB() []byte{
	var db = []byte(
`

var footer = `)
	return decompress(db)
}

func decompress(b []byte) []byte {
	r := bytes.NewReader(b)
	zr , e := zlib.NewReader(r)
	if e != nil {
		panic(e)
	}
	w := new(bytes.Buffer)
	io.Copy(w, zr)
	return w.Bytes()
}`
