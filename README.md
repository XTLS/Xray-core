# 🎮 GameTunnel Core

A UDP transport extension for [xray-core](https://github.com/XTLS/Xray-core), designed for low-latency gaming and streaming.

## Features

- **UDP transport** - minimal latency, no TCP overhead or head-of-line blocking
- **QUIC-like packet structure** - traffic looks like standard QUIC
- **ChaCha20-Poly1305** - authenticated encryption
- **Curve25519** - key exchange with Perfect Forward Secrecy
- **Pre-Shared Key** - additional authentication layer
- **Padding** - packet size masking
- **Server chaining** - route traffic through multiple nodes
- **Web server fallback** - host a website on the same port
- **Compatible with xray-core** - works alongside tcp, ws, kcp, grpc, and other transports

## Use Cases

GameTunnel is built for scenarios where **low latency and stability** matter:

- 🎮 Connecting to game servers in another region
- 🎬 Video and audio streaming
- 📡 Remote desktop access
- 🌐 Accessing your own servers and infrastructure

## Quick Start

### Server Installation

Supported OS: Ubuntu 22.04+, Debian 12+

```bash
curl -LO https://github.com/it2konst/gametunnel-core/releases/latest/download/xray-gametunnel-linux-amd64.tar.gz
tar xzf xray-gametunnel-linux-amd64.tar.gz
chmod +x xray-gametunnel
sudo cp xray-gametunnel /usr/local/bin/

# Generate UUID
xray-gametunnel uuid
```

### Server Configuration

```bash
sudo nano /etc/xray-gametunnel.json
```

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "YOUR_UUID", "flow": "" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "gametunnel",
        "gametunnelSettings": {
          "obfuscation": "quic",
          "priority": "gaming",
          "mtu": 1400,
          "enablePadding": true,
          "keepAliveInterval": 15,
          "key": "YOUR_SECRET_KEY"
        }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
```

> **Important:** `key` must match on both server and client. `flow` must be empty.

### Systemd Service

```bash
sudo tee /etc/systemd/system/xray-gametunnel.service > /dev/null << 'EOF'
[Unit]
Description=Xray GameTunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/xray-gametunnel run -c /etc/xray-gametunnel.json
Restart=on-failure
RestartSec=3
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now xray-gametunnel
```

## Client

### Option 1 - Terminal

```json
{
  "inbounds": [
    { "port": 10808, "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "SERVER_IP",
            "port": 443,
            "users": [{ "id": "YOUR_UUID", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": {
        "network": "gametunnel",
        "gametunnelSettings": {
          "obfuscation": "quic",
          "priority": "gaming",
          "mtu": 1400,
          "enablePadding": true,
          "keepAliveInterval": 15,
          "key": "YOUR_SECRET_KEY"
        }
      }
    }
  ]
}
```

```bash
./xray-gametunnel run -c client.json
curl --socks5-hostname 127.0.0.1:10808 https://ifconfig.me
```

## Hosting a Website on the Same Server

GameTunnel uses UDP while HTTPS uses TCP - both can share port 443. You can host a regular website alongside the tunnel.

### Install nginx and get SSL certificate

```bash
apt install nginx certbot -y
systemctl stop nginx
certbot certonly --standalone -d your.domain.com
systemctl start nginx
```

### Configure nginx

```nginx
server {
    listen 80;
    server_name your.domain.com;
    return 301 https://$http_host$request_uri;
}
server {
    listen 127.0.0.1:8080 http2;
    server_name your.domain.com;
    root /var/www/html/;
    index index.html;
    add_header Strict-Transport-Security "max-age=63072000" always;
}
```

### Add VLESS TCP fallback to xray config

Add a second inbound alongside the GameTunnel inbound:

```json
{
  "port": 443,
  "protocol": "vless",
  "tag": "vless-tcp",
  "settings": {
    "clients": [{ "id": "YOUR_UUID", "flow": "" }],
    "decryption": "none",
    "fallbacks": [{ "alpn": "h2", "dest": 8080 }, { "dest": 8080 }]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "alpn": ["h2", "http/1.1"],
      "certificates": [
        {
          "certificateFile": "/etc/letsencrypt/live/your.domain.com/fullchain.pem",
          "keyFile": "/etc/letsencrypt/live/your.domain.com/privkey.pem"
        }
      ]
    }
  }
}
```

Regular browsers see your website at `https://your.domain.com`, while GameTunnel clients connect over UDP on the same port.

## Server Chaining

GameTunnel supports routing through multiple nodes:

```
Client → GameTunnel(UDP) → Server A → VLESS(TCP) → Server B → internet
```

Configure Server A with an outbound pointing to Server B:

```json
{
  "outbounds": [
    {
      "tag": "next-hop",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "SERVER_B_IP",
            "port": 8443,
            "users": [{ "id": "UUID_B", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": { "network": "tcp" }
    }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["gt-in"], "outboundTag": "next-hop" }
    ]
  }
}
```

## Best Practices

GameTunnel is optimized for **interactive and streaming traffic** - gaming, video, web browsing. For best results:

- **Gaming & streaming** - works great, low latency and stable connections
- **Web browsing** - works well for regular browsing
- **Large downloads** (OS updates, package managers, IDE extensions) - consider routing these directly rather than through the tunnel, as UDP transport is not ideal for bulk transfers. You can configure routing rules in your client to send specific domains (e.g. update servers) via the `direct` outbound

## Building from Source

```bash
git clone https://github.com/it2konst/gametunnel-core.git
cd gametunnel-core
CGO_ENABLED=0 go build -o xray-gametunnel -trimpath -ldflags="-s -w" -v ./main
./xray-gametunnel version
```

Requires Go 1.22+.

## Architecture

```
   Client                   Server
┌───────────┐  UDP/443   ┌───────────┐
│   VLESS   │◄──────────►│   VLESS   │
│   + GT    │  ChaCha20  │   + GT    │
│ transport │  Poly1305  │ transport │
└───────────┘            └───────────┘
      │                        │
    SOCKS5                  Freedom
    :10808                 (internet)
```

**Handshake:** Curve25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305
**Packets:** QUIC Long Header format with padding and randomization
**Payload:** chunked to 1200 bytes for MTU compatibility

## Settings Reference

| Parameter          | Default  | Description                                   |
| ------------------ | -------- | --------------------------------------------- |
| obfuscation        | `quic`   | Traffic masking: `quic`, `webrtc`, `raw`      |
| priority           | `gaming` | Prioritization: `gaming`, `streaming`, `none` |
| mtu                | `1400`   | Max UDP packet size                           |
| enablePadding      | `true`   | Add random padding to packets                 |
| keepAliveInterval  | `15`     | Keep-alive interval (seconds)                 |
| key                | `""`     | Pre-shared key for authentication             |
| maxStreams         | `16`     | Max multiplexed streams                       |
| connectionIdLength | `8`      | Connection ID length (bytes)                  |

## Useful Commands

```bash
# Server status
sudo systemctl status xray-gametunnel

# Logs
sudo journalctl -u xray-gametunnel -f

# Monitor traffic
sudo tcpdump -i any udp port 443 -c 20 -n

# Validate config
xray-gametunnel run -test -c /etc/xray-gametunnel.json
```

## License

MPL-2.0 - inherited from [xray-core](https://github.com/XTLS/Xray-core/blob/main/LICENSE).
