# Xray-core 项目文档

## 1. 项目概览

**Xray-core** 是一个用于构建网络代理的平台，源于 XTLS 协议。它是 v2ray-core 的超集，提供增强的性能和额外功能。它支持多种网络协议，包括 VLESS、VMess、Trojan、Shadowsocks、Socks、HTTP 等。Xray-core 使用 Go 语言编写，设计上具有模块化和灵活性的特点。

主要特性包括：
- **多协议支持：** VLESS、REALITY、VMess、Trojan、Shadowsocks 等。
- **XTLS：** 一种高性能的传输层安全协议。
- **灵活路由：** 基于域名、IP、端口、地理位置等的强大路由能力。
- **可观测性：** 内置指标（metrics）和统计（statistics）。
- **跨平台：** 可在 Linux、macOS、Windows、BSD 等平台上运行。

## 2. 架构

Xray-core 遵循模块化架构：

- **核心 (`core`)：** 管理应用程序的生命周期，包括配置加载和服务器启动。
- **应用 (`app`)：** 包含主要的应用程序模块，例如：
    - `dispatcher`：将流量分发到适当的处理程序。
    - `proxyman`：管理入站和出站代理。
    - `router`：处理流量路由逻辑。
    - `log`：处理日志记录。
    - `dns`：内部 DNS 服务器。
- **代理 (`proxy`)：** 各种代理协议的实现（VLESS、VMess 等）。
- **传输 (`transport`)：** 传输协议的实现（TCP、mKCP、WebSocket、HTTP/2、QUIC、GRPC）。
- **基础设施 (`infra`)：** 基础设施组件，如配置解析 (`conf`)。

## 3. 安装与构建

### 3.1. 源码构建

**要求：**
- Go 1.20+ (请检查 `go.mod` 以获取确切版本)

**构建命令：**

*Windows (PowerShell):*
```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

*Linux / macOS:*
```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### 3.2. 安装脚本

Linux 官方安装脚本：
- [XTLS/Xray-install](https://github.com/XTLS/Xray-install)

## 4. 配置指南

Xray-core 支持 JSON、TOML、YAML 和 Protobuf 格式的配置。JSON 是最常用的格式。

### 4.1. 文件位置

默认情况下，Xray 按以下顺序查找配置文件：
1. 通过 `-c` 或 `-config` 标志指定的文件。
2. 当前工作目录下的 `config.json`（及其他扩展名）。
3. 环境变量定义的路径。

### 4.2. 配置结构 (JSON)

配置文件是一个具有以下顶级键的 JSON 对象：

```json
{
  "log": {},
  "api": {},
  "dns": {},
  "routing": {},
  "policy": {},
  "inbounds": [],
  "outbounds": [],
  "stats": {},
  "reverse": {},
  "fakeDns": {},
  "observatory": {},
  "burstObservatory": {}
}
```

#### 4.2.1. 日志 (`log`)

配置日志记录行为。

```json
"log": {
  "access": "/path/to/access.log",
  "error": "/path/to/error.log",
  "loglevel": "warning",
  "dnsLog": false
}
```
- `loglevel`： "debug", "info", "warning", "error", "none"。

#### 4.2.2. 入站 (`inbounds`)

定义 Xray 如何接收连接的对象数组。

```json
"inbounds": [
  {
    "tag": "inbound-tag",
    "port": 1080,
    "listen": "127.0.0.1",
    "protocol": "socks",
    "settings": {
      "auth": "noauth",
      "udp": true
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls"]
    }
  }
]
```
- 支持的协议：`dokodemo-door`, `http`, `shadowsocks`, `socks`, `vless`, `vmess`, `trojan`, `wireguard`。

#### 4.2.3. 出站 (`outbounds`)

定义 Xray 如何发送连接的对象数组。

```json
"outbounds": [
  {
    "tag": "proxy",
    "protocol": "vless",
    "settings": {
      "vnext": [
        {
          "address": "example.com",
          "port": 443,
          "users": [{"id": "uuid"}]
        }
      ]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "xtls"
    }
  },
  {
    "tag": "direct",
    "protocol": "freedom"
  },
  {
    "tag": "block",
    "protocol": "blackhole"
  }
]
```
- 支持的协议：`blackhole`, `freedom` (直连), `http`, `shadowsocks`, `socks`, `vless`, `vmess`, `trojan`, `dns`, `wireguard`, `loopback`。

#### 4.2.4. 路由 (`routing`)

根据规则控制流量的路由方式。

```json
"routing": {
  "domainStrategy": "IPIfNonMatch",
  "rules": [
    {
      "type": "field",
      "domain": ["geosite:google"],
      "outboundTag": "proxy"
    },
    {
      "type": "field",
      "ip": ["geoip:cn", "geoip:private"],
      "outboundTag": "direct"
    }
  ],
  "balancers": []
}
```
- `domainStrategy`：`AsIs`, `IPIfNonMatch`, `IPOnDemand`。
- `rules`：基于 `domain`（域名）、`ip`、`port`（端口）、`network`（网络）、`source`（源）、`user`（用户）、`inboundTag`（入站标签）、`protocol`（协议）匹配流量。

#### 4.2.5. DNS (`dns`)

用于域名解析的内置 DNS 服务器配置。

```json
"dns": {
  "servers": [
    "1.1.1.1",
    "8.8.8.8",
    "localhost"
  ]
}
```

## 5. 命令行接口

`xray` 二进制文件支持以下命令：

### `xray run`
运行 Xray 服务器（默认命令）。

```bash
xray run -c config.json
```

**标志：**
- `-c`, `-config`：配置文件路径（可多次使用）。
- `-confdir`：包含多个配置文件的目录。
- `-format`：配置格式 (`json`, `toml`, `yaml`, `auto`)。
- `-test`：仅测试配置有效性而不启动服务器。
- `-dump`：转储合并后的配置并退出。

### `xray version`
打印版本信息。

```bash
xray version
```

## 6. 关键协议

### VLESS
一种轻量级协议，不依赖于系统时间。它旨在高效运行，通常与 XTLS 或 REALITY 配合使用。

### XTLS
一种传输协议，减少了封装 TLS 流量时的冗余，为 TLS 加密流量提供更好的性能。

### REALITY
一种新技术，旨在取代传统的 TLS 实现，允许 Xray 伪装成其他网站，并在某些设置中消除了对注册域名的需求。

## 7. 可观测性

Xray 提供 `metrics` 和 `stats` 模块来监控流量使用情况和服务器健康状况。这些可以通过 API 暴露，或在内部用于路由决策（例如负载均衡）。
