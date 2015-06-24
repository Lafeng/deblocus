package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	app_name    = "deblocus"
	project_url = "https://github.com/spance/delocus"
	ver_major   = uint8(0)
	ver_minor   = uint8(8)
	ver_build   = uint16(175)*10 + 0
)

var build_flag string // -ldflags "-X main.build_flag -alpha"

var version uint32

func init() {
	var ver uint32
	ver |= uint32(ver_major) << 24
	ver |= uint32(ver_minor) << 16
	ver |= uint32(ver_build)
	version = ver
}

func versionString() string {
	return fmt.Sprintf("%s version: %d.%d.%04d%s\n", app_name, ver_major, ver_minor, ver_build, build_flag)
}

type CArg struct {
	literal string
	usage   string
}

func showUsage() {
	fmt.Printf("Usage: %s [-OPTION=VALUE]...\n", filepath.Base(os.Args[0]))
	fmt.Printf("%s project: <%s>\n", app_name, project_url)
	fmt.Println(versionString())

	var group = map[string][]*CArg{}
	var common = "Common"
	flag.VisitAll(func(flag *flag.Flag) {
		var literal string
		if len(flag.DefValue) > 0 {
			format := "-%s=%s"
			if strings.Contains(reflect.TypeOf(flag.Value).String(), "string") {
				// put quotes on the value
				format = "-%s=%q"
			}
			literal = fmt.Sprintf(format, flag.Name, flag.DefValue)
		} else {
			literal = "-" + flag.Name
		}
		array := strings.SplitN(flag.Usage, ";;", 2)
		if len(array) != 2 {
			array = []string{common, flag.Usage}
		}
		cArg := &CArg{literal, array[1]}
		group[array[0]] = append(group[array[0]], cArg)
	})
	for k, a := range group {
		fmt.Printf("%s options:\n", k)
		for _, i := range a {
			fmt.Printf("    %-12s %s\n", i.literal, i.usage)
		}
	}
}
