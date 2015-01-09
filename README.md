# deblocus

## Introduction

deblocus is a encrypted socks5 tunnel using secure key auto-negotiation.

This is the alpha version(currently in development)

## Why develop or use ?

- client side support multiple backend servers (random select)
- c/s communication encrypted by dynamic secure key (not using password)
- server side support multiple users

This is exactly the reason I developed it. Password only identify the user's identity, and it not be used to encrypt the traffic of session, each user's communications are encrypted by secure key from auto-negotiation, it will not happen that due to the fixed key leak (fixed key encryption mode) causes network eavesdroppers could decrypt history or realtime traffic, similarly, it will not happen all the traffic is decrypted because of one user's key leak.

## Acknowledgements

deblocus evolved from the [qtunnel](https://github.com/getqujing/qtunnel), and depends on [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx) and [glog](https://github.com/golang/glog), thanks to those projects.

# deblocus 介绍

常见的对称式加密应用中，往往过多关注了加密算法，而忽视了密钥的保持才是对称加密的弱点，比如：使用固定的密码/密钥时如何妥善管理和分发密钥，在他人窃听的密文还未销毁前如何妥善的保存密钥，固定密钥更无法避免密钥泄露后通信甚至历史流量被解密。

deblocus就是着重解决和避免静态加密方式的诸多弱点，这是一个轻量级的使用密钥自协商的socks5加密隧道。

deblocus的通信过程借鉴了https握手，精简了过程使得通信特征不明显且更局部化和轻量快速， client侧工作在用户本地，server侧工作在远程服务提供者，client server是同一可执行文件。

# 编译

假设已经安装了git和golang环境，下载了项目源包

执行 `script/build.sh` (for linux/mac) 或 `script/build_win.bat` (for windows)

# 配置

默认配置d5s/d5c会从可执行文件目录、用户家目录中尝试，否则用-config参数指定。

## deblocus-server

使用-serv参数或将可执行文件首字母大写进入server模式

生成server config文件， `./deblocus -csc > deblocus.d5s` 生成deblocus.d5s配置

创建一个文件文件 e.g. `/path/user_db.txt` 其中加入`USER:PASSWORD`形式的用户

修改deblocus.d5s中`AuthTable`的值为`/path/user_db.txt`

修改Listen监听地址端口 e.g. `1.1.1.1:9008`

修改Algo加密算法(RC4,AES128CFB,AES256CFB)

发布用户凭证 `./deblocus -icc USER1 > deblocus.d5c` 发给USER1用户凭证

## deblocus-client

若d5c配置在默认位置，则`./deblocus`启动客户端

用户需在d5c配置中加入一行`Listen  :9009`表明socks5服务端口