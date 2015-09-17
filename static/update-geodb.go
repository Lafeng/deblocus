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
	"fmt"
	"github.com/Lafeng/deblocus/geo"
	"os"
	"strconv"
	"strings"
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

	dst := init_files()
	defer func() {
		dst.Close()
		os.Rename(dst.Name(), db_file)
	}()
	dw := build()
	dw.writeDone(dst)
	fmt.Println("update done.")
}

func init_files() *os.File {
	throwIf(IsNotExist(geo.GEO2_IPV4_FILE), geo.GEO2_IPV4_FILE)
	throwIf(IsNotExist(geo.GEO2_LOC_FILE), geo.GEO2_LOC_FILE)
	dstFile, e := os.OpenFile(db_file+".tmp", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666)
	throwIf(e != nil, "OpenFile %s %v", db_file, e)
	return dstFile
}

func build() *dbWriter {
	reader := new(geo.GeoLite2Reader)
	tab := reader.ReadToRoutingTable()
	t, b, p := geo.Serialize(tab)
	dw := newDbWriter()
	dw.writeEntry(t)
	dw.writeEntry(b)
	dw.writeEntry(p)
	return dw
}

type dbWriter struct {
	entries []*bytes.Buffer
	cnt     int
}

func newDbWriter() *dbWriter {
	return &dbWriter{entries: make([]*bytes.Buffer, 0)}
}

func (dw *dbWriter) writeEntry(data []byte) {
	buf := new(bytes.Buffer)
	w := zlib.NewWriter(buf)
	w.Write(data)
	w.Flush()
	w.Close()
	dw.entries = append(dw.entries, buf)
}

func (dw *dbWriter) writeDone(fp *os.File) {
	bufw := bufio.NewWriter(fp)
	bufw.WriteString(header)
	// return part of func signature
	bufw.WriteByte('(')
	fnSign := strings.Repeat("[]byte, ", len(dw.entries))
	bufw.WriteString(fnSign[:len(fnSign)-2])
	bufw.WriteString(") {\n")
	var fnReturn = "return "
	// each entry
	for i, e := range dw.entries {
		bufw.WriteString(fmt.Sprintf("var db%d = []byte(", i))
		fnReturn += fmt.Sprintf("decompress(db%d), ", i)
		bufw.WriteString(strconv.QuoteToASCII(string(e.Bytes())))
		bufw.WriteString(")\n")
	}
	// func return
	bufw.WriteString(fnReturn[:len(fnReturn)-2])
	bufw.WriteString("\n}\n")
	bufw.WriteString(footer)
	bufw.Flush()
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

func buildGeoDB() `

var footer = `

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
