# Deblocus

[![Build Status](https://travis-ci.org/Lafeng/deblocus.svg?branch=master)](https://travis-ci.org/Lafeng/deblocus)
[![MIT License](https://img.shields.io/packagist/l/doctrine/orm.svg)](http://opensource.org/licenses/MIT)
[![Issues](https://img.shields.io/github/issues/Lafeng/deblocus.svg)](https://github.com/Lafeng/deblocus/issues)
[![Comment-on-Github.Party](https://img.shields.io/badge/Comment%20on-Github.Party-yellow.svg)](https://github.party/item?id=46)

Current version is v0.9.2520-beta

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

Deblocus is a tunneling software that allows secure TCP connection through the server by acting as a SOCKS5/HTTP proxy server on the client side.

![deblocus-introduction.png](https://i.imgur.com/FP5A7hE.png)

## Features

1. Traffic encrypted with dynamic session key
2. Client–server model
3. TCP multiplexing inside tunnel
4. Fast Open (nearly 1-RTT responded)

Explanations:

1. Deblocus has [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy).
2. You can share a server with friends.
3. Massive short requests can be accelerated.
4. Latency greatly reduced.

## Quickstart

1. Download [binary](https://github.com/Lafeng/deblocus/releases) or compile it from source.
2. Read [Wiki](https://github.com/Lafeng/deblocus/wiki).

### Simple GUI for Windows

This tool can minimize deblocus to tray.

![deblocusMonitor.png](https://i.imgur.com/pdBpKN6m.png)

Download [deblocusMonitor](https://github.com/Lafeng/deblocus/releases).

## Acknowledgements

Thanks to these projects: [qtunnel](https://github.com/getqujing/qtunnel), [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx) and [glog](https://github.com/golang/glog).

## License

[MIT License](https://github.com/Lafeng/deblocus/blob/master/LICENSE)


# Deblocus

## 介绍

建立与远端网关的加密通道，为本地应用提供安全高效的局部代理(Socks5/Http)服务。

可以满足在企业网络/公共Wifi等情景下通信被窃听或拦截时高保密、高隐私的通信需要。

## 使用

详见 [Wiki](https://github.com/Lafeng/deblocus/wiki)，程序可从项目Releases直接下载.
