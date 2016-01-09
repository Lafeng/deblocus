// -----------------  update-webpanel.go  -----------------
// The directory `static` is just for keeping static resources and tools.
// This file will NOT be compiled into deblocus executable file.
// This is a independent tool for generating or updating the `deblocus/tunnel/webpanel.go`.
// Usage:
//     cd deblocus/static
//     go run update-webpanel.go
// -----------------------------------------------------
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const (
	src_file  = "webpanel.html"
	out_file  = "../tunnel/webpanel.go"
	self_name = "update-webpanel.go"
)

func IsNotExist(file string) bool {
	_, err := os.Stat(file)
	return os.IsNotExist(err)
}

func main() {
	if IsNotExist(self_name) {
		log.Fatalln("Please change cwd to `deblocus/static`")
	}

	content, err := ioutil.ReadFile(src_file)
	if err != nil {
		log.Fatalln(err)
	}
	out, err := os.OpenFile(out_file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	defer out.Close()

	fmt.Fprint(out, format, "`")
	out.Write(content)
	fmt.Fprintln(out, "`")
	fmt.Println("Update done.")
}

const format = `package tunnel

const _TPL_WEBPANEL = `
