# deblocus  [![Build Status](https://travis-ci.org/spance/deblocus.svg?branch=master)](https://travis-ci.org/spance/deblocus)  [![MIT License](https://img.shields.io/packagist/l/doctrine/orm.svg)](http://opensource.org/licenses/MIT)  [![Issues](https://img.shields.io/github/issues/spance/deblocus.svg)](https://github.com/spance/deblocus/issues) [![Comment-on-Github.Party](https://img.shields.io/badge/Comment%20on-Github.Party-yellow.svg)](https://github.party/item?id=46)

# Introduction

deblocus is similar to VPN, could establish encrypted tunnels with the remote gateway to achieve access to the remote network, and  provide secure and high efficient proxy (socks5/http) service locally. 

![deblocus-introduction.png](https://i.imgur.com/dDNwGul.png)

# Features

There is some finished features:

- Tunnel traffic is encrypted by dynamic unique secert-key per session (not fixed password)
- C/S supports multiple peers and distributing payloads parallelly.
- using tcp multiplexer for inter endpoints of tunnel.

What does it mean?

- Don't worry about history traffic could be decrypted by others in anytime (Past, future, and present you will be at risk if lost password based on fixed-key encryption)
- Could share server with friends, and use multiple servers to offload single gateway traffic.
- Lots of short request will be accelerated by multiplexer through tunnel (if have high packet lose rate or establish new network connection difficultly on your access network or transmission network, it will save time from without TCP 3-handshakes, and save much time  from if establish new connection when syn or ack+syn lost until tcp stack waiting timeout. Dose nothing but the acceleration is existing  really that cause of using old established connection has complete lost detection and fast restransmit from tcp stack)

# Usage

Building deblocus from source is easy, and there's a
[guide](https://github.com/spance/deblocus/wiki/) that describes it for both Unix/Windows.
or [Get the Latest Release binaries here](https://github.com/spance/deblocus/releases)

# Acknowledgements

[qtunnel](https://github.com/getqujing/qtunnel), [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx) and [glog](https://github.com/golang/glog), thanks to those projects.

# Code License:

[MIT License](https://github.com/tvvocold/deblocus/blob/master/LICENSE)

# Icon License:

[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/)

[![](https://github.com/tvvocold/deblocus/blob/master/logo.png)](https://github.com/tvvocold)

# 介绍

类似VPN的网络工具，建立与远端网关的加密通道，实现接入远端网络，在本地提供安全高效的局部代理(socks5/http)服务。
可以满足在企业内网、通信窃听及拦截等不可靠链路上的实现高保密的通信需要。

# 使用

说明详见 [Wiki](https://github.com/spance/deblocus/wiki)

下载可从项目Releases.
