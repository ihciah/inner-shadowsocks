inner-shadowsocks

English

This is a simple app like ss-local in Golang. It is designed for running on a server inside China mainland and connecting a server outside through shadowsocks, then you can simply set SOCKS5 proxy in your Chrome, Telegram etc. without running a client on your laptop or cell phones.

There is a python version of this app: shadowsocks-with-socks-auth, which is just a small modified version of original shadowsocks adding SOCKS5 auth support. This go version is more efficient and support multi-server balance.

---

Features:

- SOCKS5 auth
- multi-server for load balance

Usage:

    Emmm?

Configure file:

A json string like

    {
      "listen": "0.0.0.0",
      "port": 23333,
      "auth": true,
      "username": "ihc",
      "password": "iah",
      "servers": ["ss://RC4-MD5:pass1@ip1:port1", "ss://RC4-MD5:pass2@ip2:port2"],
      "maxfail": 3,
      "recovertime": 600
    }

The auth, username,password ,maxfail, recovertime are optional whose default value are false, "", "", 10, 600 .

If you set auth to true, you should provide username and password.

You should list your servers in order. If one of them cannot be connected for maxfail times, it will be marked as downed-server until recovertime seconds later.



---

中文

这是一个类似ss-local的小程序，使用Golang编写。你可以在一台中国大陆的服务器上运行它，它可以使用shadowsocks 协议与境外服务器通信，并打开一个SOCKS5 代理提供给国内用户。此应用可以免掉运行shadowsocks客户端的麻烦，你可以直接在Chrome或者Telegram等应用内设置SOCKS5代理越过封锁。

shadowsocks-with-socks-auth 是一个python版shadowsocks的修改版，添加了SOCKS5用户认证功能。本应用比这个运行更高效，并且添加了保证高可用性的负载均衡功能。


