# Xray-core Project Documentation

## 1. Project Overview

**Xray-core** is a platform for building network proxies, originating from the XTLS protocol. It is a superset of v2ray-core, providing enhanced performance and additional features. It supports multiple network protocols including VLESS, VMess, Trojan, Shadowsocks, Socks, HTTP, and more. Xray-core is written in Go and is designed to be modular and flexible.

Key features include:
- **Multi-Protocol Support:** VLESS, REALITY, VMess, Trojan, Shadowsocks, etc.
- **XTLS:** A high-performance transport layer security protocol.
- **Flexible Routing:** Powerful routing capabilities based on domain, IP, port, geo-location, etc.
- **Observability:** Built-in metrics and statistics.
- **Cross-Platform:** Runs on Linux, macOS, Windows, BSD, etc.

## 2. Architecture

Xray-core follows a modular architecture:

- **Core (`core`):** Manages the lifecycle of the application, including configuration loading and server startup.
- **App (`app`):** Contains major application modules such as:
    - `dispatcher`: Dispatches traffic to appropriate handlers.
    - `proxyman`: Manages inbound and outbound proxies.
    - `router`: Handles traffic routing logic.
    - `log`: Handles logging.
    - `dns`: Internal DNS server.
- **Proxy (`proxy`):** Implementations of various proxy protocols (VLESS, VMess, etc.).
- **Transport (`transport`):** Implementations of transport protocols (TCP, mKCP, WebSocket, HTTP/2, QUIC, GRPC).
- **Infra (`infra`):** Infrastructure components like configuration parsing (`conf`).

## 3. Installation & Build

### 3.1. Build from Source

**Requirements:**
- Go 1.20+ (Check `go.mod` for exact version)

**Build Commands:**

*Windows (PowerShell):*
```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

*Linux / macOS:*
```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### 3.2. Installation Scripts

Official installation scripts for Linux:
- [XTLS/Xray-install](https://github.com/XTLS/Xray-install)

## 4. Configuration Guide

Xray-core supports configuration in JSON, TOML, YAML, and Protobuf formats. JSON is the most commonly used format.

### 4.1. File Locations

By default, Xray looks for configuration files in the following order:
1. Specified via `-c` or `-config` flag.
2. `config.json` (and other extensions) in the current working directory.
3. Environment variable defined paths.

### 4.2. Configuration Structure (JSON)

The configuration file is a JSON object with the following top-level keys:

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

#### 4.2.1. Log (`log`)

Configures logging behavior.

```json
"log": {
  "access": "/path/to/access.log",
  "error": "/path/to/error.log",
  "loglevel": "warning",
  "dnsLog": false
}
```
- `loglevel`: "debug", "info", "warning", "error", "none".

#### 4.2.2. Inbounds (`inbounds`)

An array of objects defining how Xray receives connections.

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
- Supported protocols: `dokodemo-door`, `http`, `shadowsocks`, `socks`, `vless`, `vmess`, `trojan`, `wireguard`.

#### 4.2.3. Outbounds (`outbounds`)

An array of objects defining how Xray sends connections.

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
- Supported protocols: `blackhole`, `freedom` (direct), `http`, `shadowsocks`, `socks`, `vless`, `vmess`, `trojan`, `dns`, `wireguard`, `loopback`.

#### 4.2.4. Routing (`routing`)

Controls how traffic is routed based on rules.

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
- `domainStrategy`: `AsIs`, `IPIfNonMatch`, `IPOnDemand`.
- `rules`: Matches traffic based on `domain`, `ip`, `port`, `network`, `source`, `user`, `inboundTag`, `protocol`.

#### 4.2.5. DNS (`dns`)

Built-in DNS server configuration for domain resolution.

```json
"dns": {
  "servers": [
    "1.1.1.1",
    "8.8.8.8",
    "localhost"
  ]
}
```

## 5. Command Line Interface

The `xray` binary supports the following commands:

### `xray run`
Runs the Xray server (default command).

```bash
xray run -c config.json
```

**Flags:**
- `-c`, `-config`: Config file path (can be used multiple times).
- `-confdir`: Directory containing multiple config files.
- `-format`: Config format (`json`, `toml`, `yaml`, `auto`).
- `-test`: Test config validity without starting the server.
- `-dump`: Dump the merged configuration and exit.

### `xray version`
Prints the version information.

```bash
xray version
```

## 6. Key Protocols

### VLESS
A lightweight protocol that does not rely on system time. It is designed to be efficient and is often used with XTLS or REALITY.

### XTLS
A transport protocol that reduces redundancy when wrapping TLS traffic, offering better performance for TLS-encrypted traffic.

### REALITY
A new technology that replaces traditional TLS implementation, allowing Xray to mimic other websites and eliminate the need for a registered domain name in some setups.

## 7. Observability

Xray provides `metrics` and `stats` modules to monitor traffic usage and server health. These can be exposed via an API or used internally for routing decisions (e.g., load balancing).
