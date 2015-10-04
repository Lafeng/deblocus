# deblocus

[![Build Status](https://travis-ci.org/Lafeng/deblocus.svg?branch=master)](https://travis-ci.org/Lafeng/deblocus)
[![MIT License](https://img.shields.io/packagist/l/doctrine/orm.svg)](http://opensource.org/licenses/MIT)
[![Issues](https://img.shields.io/github/issues/Lafeng/deblocus.svg)](https://github.com/Lafeng/deblocus/issues)
[![Comment-on-Github.Party](https://img.shields.io/badge/Comment%20on-Github.Party-yellow.svg)](https://github.party/item?id=46)

Current version is v0.10.2640-beta

```
      ___         ___         ___         ___  ___         ___         ___         ___     
     /\  \       /\  \       /\  \       /\__\/\  \       /\  \       /\__\       /\  \    
    /::\  \     /::\  \     /::\  \     /:/  /::\  \     /::\  \     /:/  /      /::\  \   
   /:/\:\  \   /:/\:\  \   /:/\:\  \   /:/  /:/\:\  \   /:/\:\  \   /:/  /      /:/\ \  \  
  /:/  \:\__\ /::\~\:\  \ /::\~\:\__\ /:/  /:/  \:\  \ /:/  \:\  \ /:/  /  ___ _\:\~\ \  \ 
 /:/__/ \:|__/:/\:\ \:\__/:/\:\ \:|__/:/__/:/__/ \:\__/:/__/ \:\__/:/__/  /\__/\ \:\ \ \__\
 \:\  \ /:/  \:\~\:\ \/__\:\~\:\/:/  \:\  \:\  \ /:/  \:\  \  \/__\:\  \ /:/  \:\ \:\ \/__/
  \:\  /:/  / \:\ \:\__\  \:\ \::/  / \:\  \:\  /:/  / \:\  \      \:\  /:/  / \:\ \:\__\  
   \:\/:/  /   \:\ \/__/   \:\/:/  /   \:\  \:\/:/  /   \:\  \      \:\/:/  /   \:\/:/  /  
    \::/__/     \:\__\      \::/__/     \:\__\::/  /     \:\__\      \::/  /     \::/  /   
     ~~          \/__/       ~~          \/__/\/__/       \/__/       \/__/       \/__/    
     
     He who gives up freedom for safety deserves neither.___Benjamin Franklin
```

## Introduction

deblocus is a tunneling software that allows secure TCP connection through the server by acting as a SOCKS5/HTTP proxy server on the client side. The deblocus server shall not be shared with someone you don't trust.

![deblocus-introduction.png](https://i.imgur.com/FP5A7hE.png)

## Features

1. Traffic encrypted with dynamic session key
2. TCP multiplexing inside tunnel
3. Tunnel's communication was provided with mildly obfuscated traffic based on special protocol
4. Fast-Open over application layer (response nearly 1-RTT)
5. Filtering traffic to IPs in specified country with GeoLite2 data
6. Use high-performance encryption implementation

Explanations:

1. deblocus has [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy).
2. You can share a server with friends.
3. Massive short requests can be accelerated.
4. Latency greatly reduced.
5. You can know it when inappropriate proxy is used.
6. Could enjoy high throughput.

## Quickstart

1. Download [executables](https://github.com/Lafeng/deblocus/releases) or compile it from source.
2. Read [Wiki](https://github.com/Lafeng/deblocus/wiki).

## Applicable Scope

Architecture: x86, amd64(x86-64)

OS: windows, linux, osx

### Simple GUI for Windows

[deblocusMonitor](https://github.com/Lafeng/deblocus/releases) can minimize deblocus to tray.

![deblocusMonitor.png](https://i.imgur.com/pdBpKN6m.png)

## Acknowledgements

Thanks to these projects: [qtunnel](https://github.com/getqujing/qtunnel), [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx), [glog](https://github.com/golang/glog), [siphash](https://github.com/dchest/siphash) and [chacha-opt](https://github.com/floodyberry/chacha-opt).

This product includes GeoLite2 data created by MaxMind, available from <http://www.maxmind.com>.

## License

[MIT License](https://github.com/Lafeng/deblocus/blob/master/LICENSE)


# deblocus

## 介绍

建立与远端网关的加密通道，为本地应用提供安全高效的局部代理(Socks5/HTTP)服务。

可以满足在企业网络/公共Wifi等情景下通信被窃听或拦截时高保密、高隐私的通信需要。

## 使用

详见 [Wiki](https://github.com/Lafeng/deblocus/wiki)，程序可从项目Releases直接下载.
