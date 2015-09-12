package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
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
	rw, e := convertTo10bit()
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
	writeFile(rw)
}

func convertTo10bit() (rw *bytes.Buffer, e error) {
	defer func() {
		ex := recover()
		if ex != nil {
			e = fmt.Errorf("%v", ex)
		}
	}()
	csvfile, e := os.Open(geo_file)
	throwIf(e != nil, "open %s %v", geo_file, e)
	defer csvfile.Close()
	rw = new(bytes.Buffer)
	rw.Grow(0xffff)
	r := csv.NewReader(csvfile)
	buf := make([]byte, 10)
	for {
		fields, e := r.Read()
		if e == io.EOF {
			break
		} else {
			throwIf(e != nil, "Read %s %v", csvfile, e)
		}
		start, e := strconv.ParseUint(fields[2], 10, 32)
		throwIf(e != nil, "ParseUint %s %v", fields[2], e)
		binary.BigEndian.PutUint32(buf, uint32(start))
		end, e := strconv.ParseUint(fields[3], 10, 32)
		throwIf(e != nil, "ParseUint %s %v", fields[3], e)
		binary.BigEndian.PutUint32(buf[4:], uint32(end))
		copy(buf[8:], []byte(fields[4]))
		n, e := rw.Write(buf)
		throwIf(n != 10 || e != nil, "Write memory %v", e)
	}
	return
}

var header = `package geo

import (
	"github.com/alecthomas/gobundle"
)

var DbBundle *gobundle.Bundle = gobundle.NewBuilder("geo").Compressed().UncompressOnInit().Add(
	"ranges.db", []byte{
`

var footer = `	},
).Build()`

func writeFile(r io.Reader) {
	dbfile, e := os.OpenFile(db_file, os.O_CREATE|os.O_RDWR, 0666)
	throwIf(e != nil, "OpenFile %v %v", dbfile, e)
	defer dbfile.Close()
	trw := new(bytes.Buffer)
	z := zlib.NewWriter(trw)
	_, e = io.Copy(z, r)
	z.Flush()
	z.Close()
	r = nil
	throwIf(e != nil, "copy memory %v", e)

	dbfile.WriteString(header)
	throwIf(e != nil, "Write dbfile %v", e)
	line := make([]byte, 12)
	for i, max := 0, trw.Len(); i < max; {
		n, e := trw.Read(line)
		i += n
		if n > 0 {
			literal := fmt.Sprintf(" % x", line[:n])
			literal = strings.Replace(literal, " ", ", 0x", -1)
			literal = "\t\t" + literal[2:] + ",\n" // skip leading ,+space
			dbfile.WriteString(literal)
		}
		if e == io.EOF {
			break
		} else {
			throwIf(e != nil, "Read memory %v", e)
		}
	}
	dbfile.WriteString(footer)
	throwIf(e != nil, "Write dbfile %v", e)
}

func IsNotExist(file string) bool {
	_, err := os.Stat(file)
	return os.IsNotExist(err)
}
