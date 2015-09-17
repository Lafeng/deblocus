#!/bin/bash

# env.global: TARGET_ARCH=amd64
# before_deploy matrix export: GOARCH=$TARGET_ARCH GOOS=$TARGET_OS $EXT

if [ -n "$TRAVIS_BUILD_NUMBER" ]; then
	BVER=${TRAVIS_BUILD_NUMBER}_`echo $TRAVIS_COMMIT | head -c 7`
	OUTPUT=deblocus_${BVER}_$GOOS-$GOARCH.tgz
	go build -ldflags "-X main.build_flag=-dev-$BVER"
	if [ $? == 0 ]; then
		tar cvaf $OUTPUT deblocus$EXT
		curl -H "X-Auth: `echo -n $OUTPUT$token | sha1sum | head -c 40`" -T $OUTPUT $url > /dev/null 2>&1
		rm deblocus$EXT $OUTPUT
	fi
	exit 0
fi
echo "Hello deblocus!"
