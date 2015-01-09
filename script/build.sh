#!/bin/bash

echo deblocus build script

scriptdir=$(dirname $(readlink -f $0))
project=`readlink -f $scriptdir/..`

function download {
    local _file="$1"
    if [[ ! -e $_file ]]; then
        local _wget=`which wget`
        local _curl=`which curl`
        
        if [[ -z $_wget || -z $_curl ]]; then
            echo "Need curl or wget in env.PATH"
            exit 1
        fi
        local _url="$2"
        if [[ -n $_wget ]]; then
            wget -O $_file $_url
        else
            curl -o $_file $_url
        fi
    fi
}

function installOsext {
    if [[ -f "$osext_path/osext.go" ]]; then
        return 0
    fi
    
    cd $scriptdir
    osext_file="osext.tar.gz"
    osext_url="https://bitbucket.org/kardianos/osext/get/default.tar.gz"
    download $osext_file $osext_url
    
    mkdir -p $osext_path
    tar --strip-components=1 -xzf $osext_file -C $osext_path
    return $?
}

function clean {
    cd $project
    echo "go clean"
    GOPATH=$project go clean
}

function build {
    _go=`which go`
    if [[ -z _go ]]; then
        echo "Need golang/bin in env.PATH"
        exit 1
    fi

    osext_path="$project/src/bitbucket.org/kardianos/osext"
    _hg=`which hg`
    if [[ -z $_hg ]]; then
        installOsext
    fi

    echo -e "\nbuilding (may download dependencies) ..."

    cd $project
    GOPATH=$project go get deblocus
    if [[ $? == 0 ]]; then
        echo deblocus build done: $project/bin
    fi
}

case "$1" in
clean)
    clean
    ;;
# install)
# ;;
*)
    build
    ;;
esac
