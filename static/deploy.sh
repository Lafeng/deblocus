#!/bin/bash

# env.global: TARGET_ARCH=amd64
# before_deploy matrix export: GOARCH=$TARGET_ARCH GOOS=$TARGET_OS

if [ "$GOOS" = "windows" ]; then
	export CC=x86_64-w64-mingw32-gcc
fi

if [ -n "$TRAVIS_BUILD_NUMBER" ]; then
	BVER=${TRAVIS_BUILD_NUMBER}_`echo $TRAVIS_COMMIT | head -c 7`
	TARBALL=deblocus-$BVER-$GOOS-$GOARCH.tgz
	BINARY=deblocus`go env GOEXE`
	LDFLAGS="-X main.build_flag=-dev-$BVER"
	
	# check glibc version
	# travis ubuntu "glibc 2.19"
	currentGOOS=`go env GOOS`
	getconf GNU_LIBC_VERSION | awk '{if($2>=2.14){exit 1}}'
	if [ $? -eq 1 -a "$currentGOOS" = "linux" ]; then
		LDFLAGS="$LDFLAGS -extldflags -Wl,--wrap=memcpy"
	fi
	
	# cwd=deblocus
	go build -ldflags "$LDFLAGS"
	if [ $? -eq 0 ]; then
		tar caf $TARBALL $BINARY
		ls -l deblocus*
		curl -H "X-Auth: `echo -n $TARBALL$token | sha1sum | head -c 40`" -T $TARBALL $url > /dev/null 2>&1
		rm -f $BINARY $TARBALL
	fi
	exit 0
fi

echo "Hello deblocus!"
