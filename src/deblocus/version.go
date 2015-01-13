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
	ver_major   = "0.5"
	ver_minor   = "0130" + "-alpha"
)

func versionString() string {
	return fmt.Sprintf("%s version: %s.%s\n", app_name, ver_major, ver_minor)
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
