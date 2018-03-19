# inner-shadowsocks #

[English](#english) | [中文](#中文)

### English

This is a simple app like `ss-local` in Golang. It is designed for running on a server inside China mainland and connecting a server outside through `shadowsocks`, then you can simply set `SOCKS5` proxy in your Chrome, Telegram etc. without running a client on your laptop or cell phones.

There is a python version of this app: [shadowsocks-with-socks-auth](https://github.com/ihciah/shadowsocks-with-socks-auth), which is just a small modified version of original shadowsocks adding `SOCKS5` auth support. This go version is more efficient and support multi-server balance.

-----

#### Features:

- `SOCKS5` auth
- multi-server for load balance

#### Install:

Way 1: Download binary from [Releases](https://github.com/ihciah/inner-shadowsocks/releases). Golang environment is not required.

Way 2:

```shell
go get -u -v github.com/ihciah/inner-shadowsocks/inner-ss
```

Due to network issue in China mainland, in most situation, `go get` cannot be executed correctly.

#### Usage:

```shell
inner-ss -c config.json
```

- -c: configure file path(default: `config.json`)
- -v: verbose mode

Configure file:

A json string like

```json
{
  "listen": "0.0.0.0",
  "port": 23333,
  "auth": true,
  "username": "ihc",
  "password": "iah",
  "servers": ["ss://RC4-MD5:pass1@ip1:port1", "ss://RC4-MD5:pass2@ip2:port2"],
  "maxfail": 3,
  "recovertime": 600,
  "remotetimeout": 6,
  "insidetimeout": 3
}
```

The `auth`, `username`,`password` ,`maxfail`, `recovertime`, `remotetimeout`, `insidetimeout` are optional whose default value are `false`, `""`, `""`, `10`, `600`, `6`, `3` .

If you set `auth` to `true`, you should provide `username` and `password`.

You should list your servers in order. If one of them cannot be connected for `maxfail` times, it will be marked as downed-server until `recovertime` seconds later. Please pay attention that you must ensure the password and encryption method is correct. Because we cannot distinguish users' malicious requests and the wrong password of shadowsocks servers, here we judge server status through if we can connect it.

`remotetimeout` is the timeout connecting remote servers, and `insidetimeout` is the one to clients.

You can use `systemd` or `supervisor` to run the daemon. The example configure of supervisor is at the bottom.



-----

### 中文

这是一个类似`ss-local`的小程序，使用Golang编写。你可以在一台中国大陆的服务器上运行它，它可以使用`shadowsocks` 协议与境外服务器通信，并打开一个`SOCKS5` 代理提供给国内用户。此应用可以免掉运行`shadowsocks`客户端的麻烦，你可以直接在Chrome或者Telegram等应用内设置`SOCKS5`代理越过封锁。

[shadowsocks-with-socks-auth](https://github.com/ihciah/shadowsocks-with-socks-auth) 是一个python版`shadowsocks`的修改版，添加了`SOCKS5`用户认证功能。本应用比这个运行更高效，并且添加了保证高可用性的负载均衡功能。

#### 功能：

- SOCKS5用户认证支持
- 多服务器负载均衡

#### 安装：

方式1(推荐)：在 [Releases](https://github.com/ihciah/inner-shadowsocks/releases) 中下载可执行文件并上传直接执行。不需要安装Go语言环境。

方式2：

```shell
go get -u -v github.com/ihciah/inner-shadowsocks/inner-ss
```

在国内服务器上执行安装，由于网络原因`go get`大概率无法顺利执行。

#### 使用：

```shell
inner-ss -c config.json
```

- -c: 配置文件路径，默认为config.json
- -v: 打印详细信息，默认关闭

配置文件样例(json格式)：

```json
{
  "listen": "0.0.0.0",
  "port": 23333,
  "auth": true,
  "username": "ihc",
  "password": "iah",
  "servers": ["ss://RC4-MD5:pass1@ip1:port1", "ss://RC4-MD5:pass2@ip2:port2"],
  "maxfail": 3,
  "recovertime": 600,
  "remotetimeout": 6,
  "insidetimeout": 3
}
```

`auth`, `username`,`password` ,`maxfail`, `recovertime`, `remotetimeout`, `insidetimeout` 这些字段是可选的，默认值为 `false`, `""`, `""`, `10`, `600`, `6`, `3`. `auth`为`true`表示开启SOCKS5认证功能，可以防止服务器被扫描器扫到并滥用，当开启认证功能时，需提供`username`和`password`。

`servers`为shadowsocks服务器配置信息，请按照排好的顺序提供。如果一个服务器无法连接，当出错次数超过`maxfail`后会被标记为不可用，该标记会在`recovertime`秒后解除。请注意shadowsocks的服务器加密方式和密码必须保证正确。我们无法判断服务器不回应是因为用户的恶意请求还是密码错误，所以为了避免负载均衡功能被用来恶意禁用服务器，我们只采用能否连接服务器作为判断依据。

`remotetimeout` 为代理服务器超时时间，`insidetimeout` 为客户端超时时间。

可以使用 `systemd` 或 `supervisor` 守护进程执行。文末附supervisor的配置文件样例。

-----

#### Supervisor Configure File Example

`/etc/supervisor/conf.d/ss4tg.conf`

```
[program:ss4tg]
directory = /opt/ss4tg
command = /opt/ss4tg/inner-ss
autostart = true
autorestart = true
startsecs = 5
startretries = 30
user = nobody
```
Then run `sudo supervisorctl reload`.