// -----------------  update-webpanel.go  -----------------
// The directory `static` is just for keeping static resources and tools.
// This file will NOT be compiled into deblocus executable file.
// This is a independent tool for generating or updating the `deblocus/tunnel/webpanel.go`.
// Usage:
//     cd deblocus/static/update-webpanel
//     go run update-webpanel.go
// -----------------------------------------------------
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"unicode"
)

const (
	src_file  = "webpanel.html"
	out_file  = "../../tunnel/webpanel.go"
	self_name = "update-webpanel.go"
	self_dir  = "deblocus/static/update-webpanel"
)

func IsNotExist(file string) bool {
	_, err := os.Stat(file)
	return os.IsNotExist(err)
}

func main() {
	if IsNotExist(self_name) {
		log.Fatalln("Please change cwd to", self_dir)
	}

	mainPage := minifyReadFile(src_file)

	out, err := os.OpenFile(out_file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	defer out.Close()

	fmt.Fprint(out, pkg_line, "\n\n")
	// 404
	fmt.Fprint(out, "const _TPL_PAGE_404 = `", tpl_404, "`\n")
	// mainpage
	fmt.Fprint(out, "const _TPL_PAGE_MAIN = `")
	out.Write(mainPage)
	fmt.Fprintln(out, "`")

	fmt.Println("Update done.")
}

func minifyReadFile(file string) []byte {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	var lastLineEnd byte
	var partMark int
	var r = bufio.NewReader(f)
	var buf = new(bytes.Buffer)
	for {
		line, part, err := r.ReadLine()
		if part {
			partMark++
		} else if partMark > 0 {
			partMark = -1
		} else {
			partMark = 0
		}
		if len(line) > 0 {
			switch partMark {
			case 0:
				line = bytes.TrimSpace(line)
			case 1:
				line = bytes.TrimLeftFunc(line, unicode.IsSpace)
			default:
				if partMark < 0 {
					partMark = 0
					line = bytes.TrimRightFunc(line, unicode.IsSpace)
				}
			}
			buf.Write(line)
			lastLineEnd = line[len(line)-1]
		}
		if err != nil && r.Buffered() == 0 {
			break
		}
	}
	// make sure line end with \n
	if lastLineEnd != '\n' {
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

const pkg_line = `package tunnel`

// make sure line end with \n
const tpl_404 = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>{{.Version}}</center></body></html>
`
