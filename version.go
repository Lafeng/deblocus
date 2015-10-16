package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const (
	app_name           = "deblocus"
	project_url        = "https://github.com/Lafeng/delocus"
	ver_major   uint8  = 0
	ver_minor   uint8  = 11
	ver_build   uint16 = 2890
)

var build_flag string // -ldflags "-X main.build_flag=-beta"

var version uint32

func init() {
	var ver uint32
	ver |= uint32(ver_major) << 24
	ver |= uint32(ver_minor) << 16
	ver |= uint32(ver_build)
	version = ver
}

func versionString() string {
	return fmt.Sprintf("%s version: v%d.%d.%04d%s", app_name, ver_major, ver_minor, ver_build, build_flag)
}

func buildInfo() string {
	return fmt.Sprintf("Built with %s %s for %s/%s", runtime.Compiler, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

type argDesc struct {
	group   string
	literal string
	usage   string
	example string
}

func showUsage() {
	fmt.Printf("Usage: %s [-OPTION=VALUE]...\n", filepath.Base(os.Args[0]))
	fmt.Printf("%s project: <%s>\n", app_name, project_url)
	fmt.Println(versionString())
	fmt.Println(buildInfo(), "\n")

	var group = make(map[string][]*argDesc)
	var common = "Common"
	// hide default value of bool and negative number
	var reHideDef, _ = regexp.Compile("^(?i:true|false|-)")

	flag.VisitAll(func(f *flag.Flag) {
		var literal string
		if len(f.DefValue) > 0 && !reHideDef.MatchString(f.DefValue) {
			literal = fmt.Sprintf("-%s=%s", f.Name, f.DefValue)
		} else {
			literal = "-" + f.Name
		}

		arg := argDesc{literal: literal}
		// split group
		array := strings.SplitN(f.Usage, ";;", 2)
		if len(array) != 2 { // common
			arg.group, arg.usage = common, f.Usage
		} else {
			arg.group, arg.usage = array[0], array[1]
		}
		// split example
		if strings.Index(arg.usage, "//") >= 0 {
			ue := strings.SplitN(arg.usage, "//", 2)
			arg.usage, arg.example = ue[0], ue[1]
		}
		group[arg.group] = append(group[arg.group], &arg)
	})

	gNames := make([]string, 0, len(group))
	for name := range group {
		gNames = append(gNames, name)
	}
	sort.Strings(gNames)

	for _, gName := range gNames {
		fmt.Printf("%s options:\n", gName)
		for _, arg := range group[gName] {
			fmt.Printf("  %-12s %s\n", arg.literal, arg.usage)
			if arg.example != "" {
				fmt.Printf("  %-12s %s\n", " ", arg.example)
			}
		}
	}
	fmt.Println("")
}
