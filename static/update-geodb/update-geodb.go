// -----------------  update-geodb.go  -----------------
// The directory `static` is just for keeping static resources and tools.
// This file will NOT be compiled into deblocus executable file.
// This is a independent tool for generating or updating the `deblocus/geo/geodb.go`.
// Usage:
//     cd deblocus/static/update-geodb
//     go run update-geodb.go
// -----------------------------------------------------
package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"fmt"
	"os"
	"strconv"

	"github.com/Lafeng/deblocus/geo"
)

const (
	db_file   = "../../geo/geodb.go"
	self_name = "update-geodb.go"
	self_dir  = "deblocus/static/update-geodb"
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
		fmt.Println("Please change cwd to", self_dir)
		os.Exit(1)
	}

	dst := init_files()
	defer func() {
		dst.Close()
		if e := recover(); e == nil {
			os.Rename(dst.Name(), db_file)
		} else {
			panic(e)
		}
	}()
	dw := build()
	dw.writeDone(dst)
	fmt.Println("Update done.")
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
	lens    []int
	cnt     int
}

func newDbWriter() *dbWriter {
	return &dbWriter{
		entries: make([]*bytes.Buffer, 0),
		lens:    make([]int, 0),
	}
}

func (dw *dbWriter) writeEntry(data []byte) {
	_len := len(data)
	dw.lens = append(dw.lens, _len)
	buf := new(bytes.Buffer)
	if _len <= 0 {
		dw.entries = append(dw.entries, buf)
	} else {
		w := zlib.NewWriter(buf)
		w.Write(data)
		w.Flush()
		w.Close()
		dw.entries = append(dw.entries, buf)
	}
}

func (dw *dbWriter) writeDone(fp *os.File) {
	bufw := bufio.NewWriter(fp)
	bufw.WriteString(header)
	// write lens
	bufw.WriteString(fmt.Sprintf("\tvar lens = %#v\n", dw.lens))
	fnReturn := "\treturn "
	// each entry
	for i, e := range dw.entries {
		if e.Len() > 0 {
			fnReturn += fmt.Sprintf("decompress(db%d, lens[%d]), ", i, i)
		} else {
			fnReturn += fmt.Sprintf("db%d, ", i)
		}
		bufw.WriteString(fmt.Sprintf("\tvar db%d = []byte(", i))
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
	"fmt"
	"io"
)

func buildGeoDB() ([]byte, []byte, []byte) {
`

var footer = `

func decompress(b []byte, lens int) []byte {
	zr, e := zlib.NewReader(bytes.NewReader(b))
	if e != nil {
		panic(e)
	}
	var nw int
	w := make([]byte, lens)
	for nw < lens {
		n, e := zr.Read(w[nw:])
		nw += n
		if e != nil {
			if e == io.EOF {
				break
			}
			panic(e)
		}
	}
	if nw != lens {
		panic(fmt.Errorf("expected len=%d but read len=%d", lens, nw))
	}
	return w
}
`
