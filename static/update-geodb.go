// -----------------  update-geodb.go  -----------------
// The directory `static` is just for keeping static resources and tools.
// This file will NOT be compiled into deblocus executable file.
// This is a independent tool for generating or updating the `deblocus/geo/geodb.go`.
// Usage:
//     cd deblocus/static
//     go run update-geodb.go
// -----------------------------------------------------
package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"github.com/Lafeng/deblocus/geo"
	"os"
	"strconv"
)

const (
	db_file   = "../geo/geodb.go"
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
		fmt.Println("Please change cwd to `deblocus/static`")
		os.Exit(1)
	}
	p := new(parser)
	p.init()
	p.parseAndWrite()
}

type parser struct {
	dstFile   *os.File
	dstBuffer *bytes.Buffer
	dstWriter *zlib.Writer
	h8Cnt     int
	lastH16   uint16
	latestLf  bool
}

func (p *parser) init() {
	var e error
	p.dstFile, e = os.OpenFile(db_file, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666)
	throwIf(e != nil, "OpenFile %s %v", db_file, e)
	p.dstBuffer = new(bytes.Buffer)
	p.dstWriter = zlib.NewWriter(p.dstBuffer)
}

func (p *parser) free() {
	if p.dstFile != nil {
		p.dstFile.Close()
	}
}

func (p *parser) parseAndWrite() {
	var (
		buf = make([]byte, 7)
	)
	reader := new(geo.GeoLite2Reader)
	var lineReader = func(fields []string) {
		// fields: cidr, id, ...
		ip, mask := geo.ParseCIDR(fields[0])
		id, _ := strconv.Atoi(fields[1])
		code := reader.CountryCode[id]
		binary.BigEndian.PutUint32(buf, ip)
		buf[4] = uint8(mask)
		copy(buf[5:], code)
		p.dstWriter.Write(buf)
	}
	reader.Iter(lineReader)
	p.writeToFile()
	fmt.Println("Done.")
}

func (p *parser) writeToFile() {
	// zlib flush and close
	p.dstWriter.Flush()
	p.dstWriter.Close()

	defer p.dstFile.Close()
	// buffered file
	dst := bufio.NewWriter(p.dstFile)
	dst.WriteString(header)
	dst.WriteString(strconv.QuoteToASCII(string(p.dstBuffer.Bytes())))
	dst.WriteString(footer)
	dst.Flush()
}

func IsNotExist(file string) bool {
	_, err := os.Stat(file)
	return os.IsNotExist(err)
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
