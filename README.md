# deblocus

## Introduction

This is the alpha version is currently under development.

deblocus is a encrypted socks5 tunnel using secure key auto-negotiation.

## Why develop or use ?

- client side support multiple backend servers (random select)
- c/s communication encrypted by dynamic secure key (not using password)
- support multiple users

This is exactly the reason I developed it. Password only identify the user's identity, and it not be used to encrypt the traffic of session, each user's communications are encrypted by auto-negotiation secure key, it will not happen that due to the fixed key leak (fixed key encryption mode) causes network eavesdroppers could decrypt history or realtime traffic, similarly, it will not happen all the traffic is decrypted because of one user's key leak.

## Details

TODO:

## Build and Install

TODO:

## Acknowledgements

deblocus evolved from the [qtunnel](https://github.com/getqujing/qtunnel), and depends on [osext](https://bitbucket.org/kardianos/osext), [dhkx](https://github.com/monnand/dhkx) and [glog](https://github.com/golang/glog), thanks to those projects.