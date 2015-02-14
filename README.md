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

### Introduction

deblocus is a secure socks5 and http proxy solution using auto negotiation of secret key.

This is the alpha version(currently in development)

### Why develop and use ?

- client side support multiple backend servers (random select) for distributing parallel payloads.
- c/s communication encrypted by dynamic secure key (not using password)
- server side support multiple users

This is the exactly reason I developed it. Password only identify the user's identity, and it not be used to encrypt the traffic of session, each user's communications are encrypted by secure key from auto-negotiation, it will not happen that due to the fixed key leak (fixed key encryption mode) causes network eavesdroppers could decrypt history or realtime traffic, similarly, it will not happen all the traffic is decrypted because of one user's key leak.

### Acknowledgements

deblocus evolved from the [qtunnel](https://github.com/getqujing/qtunnel), and depends on [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx) and [glog](https://github.com/golang/glog), thanks to those projects.

# deblocus 介绍

常见的对称加密应用中，容易忽视密钥的保存和分发才是对称加密的弱点，固定密钥一旦泄露甚至连历史流量被会解密。

deblocus就是为了**提高安全和隐私性**，这是一个轻量级的密钥自协商的socks5加密隧道，通信过程借鉴了https握手，但步骤更少和特征更少也更局部化和快速。

### 编译/配置/运行

####参见项目[Wiki](https://github.com/spance/deblocus/wiki)

### 伸手即用

####项目[Release](https://github.com/spance/deblocus/releases)中不定期发布已编译的可执行文件

###License
####[MIT](https://github.com/spance/deblocus/blob/master/LICENSE)
