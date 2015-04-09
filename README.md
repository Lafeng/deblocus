# deblocus  [![Build Status](https://travis-ci.org/spance/deblocus.svg?branch=master)](https://travis-ci.org/spance/deblocus)  [![MIT License](https://img.shields.io/packagist/l/doctrine/orm.svg)](http://opensource.org/licenses/MIT)  [![Issues](https://img.shields.io/github/issues/spance/deblocus.svg)](https://github.com/spance/deblocus/issues)

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

Introduction
-
deblocus (In development) is a new secure socks5 and http proxy solution using auto negotiation of secret key.


Features
-
The following are the deblocus' goals:
- client side support multiple backend servers (random select) for distributing parallel payloads.
- c/s communication encrypted by dynamic secure key (not using password)
- server side support multiple users

Password only identify the user's identity, and it not be used to encrypt the traffic of session, each user's communications are encrypted by secure key from auto-negotiation, it will not happen that due to the fixed key leak (fixed key encryption mode) causes network eavesdroppers could decrypt history or realtime traffic, similarly, it will not happen all the traffic is decrypted because of one user's key leak.

Usage
-
Building deblocus from source is easy, and there's a
[guide](https://github.com/spance/deblocus/wiki/) that describes it for both Unix/Windows.
or [Get the Latest Release binaries here](https://github.com/spance/deblocus/releases)

Acknowledgements
-
deblocus evolved from the [qtunnel](https://github.com/getqujing/qtunnel), and depends on [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx) and [glog](https://github.com/golang/glog), thanks to those projects.

Code License:
-
[MIT License](https://github.com/tvvocold/deblocus/blob/master/LICENSE)

Icon Licese:
-
[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0)](http://creativecommons.org/licenses/by-nc-sa/4.0/)

deblocus 介绍
-
利用客户端和远端之间建立可靠的加密通道，在客户端提供 socks5/http 代理服务，可以满足在不可靠链路上的通信、企业内网、防火墙局部阻挡等类似情况下满足高度保密和隐私性的通信需要。

deblocus 目的首先是为了保障通信的高度安全和隐私性，并且使其通信过程步骤更少、特征更少、也更局部化和快速。

使用介绍
-
参见项目 [Wiki](https://github.com/spance/deblocus/wiki)

更新日志
-
[ChangeLog](https://github.com/spance/deblocus/blob/master/CHANGELOG.md)

致谢
-
感谢 [qtunnel](https://github.com/getqujing/qtunnel), [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx), [glog](https://github.com/golang/glog)等项目.




