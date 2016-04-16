package main

import (
	"fmt"
	"runtime"
)

const (
	app_name    = "deblocus"
	project_url = "https://github.com/Lafeng/deblocus"
)

const (
	ver_major uint8  = 0
	ver_minor uint8  = 13
	ver_build uint16 = 4720 // echo $((`date +%-j`+365))
)

var (
	build_flag string // -ldflags "-X main.build_flag=-beta"
	version    uint32
)

func init() {
	version |= uint32(ver_major) << 24
	version |= uint32(ver_minor) << 16
	version |= uint32(ver_build)
}

func versionString() string {
	return fmt.Sprintf("%s version: v%d.%d.%04d%s", app_name, ver_major, ver_minor, ver_build, build_flag)
}

func buildInfo() string {
	return fmt.Sprintf("Built with %s %s for %s/%s", runtime.Compiler, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
