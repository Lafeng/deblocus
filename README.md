# deblocus

### Introduction

deblocus is a encrypted socks5 tunnel using secure key auto-negotiation.

This is the alpha version(currently in development)

### Why develop and use ?

- client side support multiple backend servers (random select)
- c/s communication encrypted by dynamic secure key (not using password)
- server side support multiple users

This is exactly the reason I developed it. Password only identify the user's identity, and it not be used to encrypt the traffic of session, each user's communications are encrypted by secure key from auto-negotiation, it will not happen that due to the fixed key leak (fixed key encryption mode) causes network eavesdroppers could decrypt history or realtime traffic, similarly, it will not happen all the traffic is decrypted because of one user's key leak.

### Acknowledgements

deblocus evolved from the [qtunnel](https://github.com/getqujing/qtunnel), and depends on [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx) and [glog](https://github.com/golang/glog), thanks to those projects.

# deblocus 介绍

常见的对称式加密应用中，容易忽视了密钥的保存和分发才是对称加密的弱点，固定密钥一旦泄露甚至连历史流量被会解密.

deblocus目的就是为了提高安全和隐私性，这是一个轻量级的密钥自协商的socks5加密隧道。

deblocus的通信过程借鉴了https握手，但步骤更少和特征更少及更局部化和快速轻量。

### 编译和配置

项目[Wiki](https://github.com/spance/deblocus/wiki)中有详细解释

### 伸手即用

项目[Release](https://github.com/spance/deblocus/releases)中不定期发布已编译的可执行文件
