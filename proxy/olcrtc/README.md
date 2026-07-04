# olcRTC proxy for Xray

`proxy/olcrtc` integrates the [olcRTC](https://github.com/openlibrecommunity/olcrtc)
encrypted TCP-over-WebRTC tunnel into this Xray fork as a first-class proxy
protocol, with **both** a client (outbound) and a server (inbound).

Traffic is disguised as an ordinary video call on an allowed SFU service
(Jitsi Meet, Yandex Telemost, WbStream) and additionally encrypted end-to-end
with a shared XChaCha20-Poly1305 key. Inside the call it multiplexes many TCP
connections (smux) over the WebRTC data/video channel.

```
app -> Xray (socks/…) -> olcrtc outbound  ══WebRTC/SFU══>  olcrtc inbound -> Xray router -> internet
```

## Roles

| Xray role | olcrtc role | Config message | JSON `protocol` |
|-----------|-------------|----------------|-----------------|
| `outbounds[]` | client (`cnc`) | `ClientConfig` | `olcrtc` |
| `inbounds[]`  | server (`srv`) | `ServerConfig` | `olcrtc` |

The **inbound is self-driven**: it has no listening socket and needs no `port`.
It dials out to the SFU room, accepts tunnel streams and dispatches each target
through Xray's router — so routing rules, DNS, domain sniffing, stats and the
chosen egress outbound (`freedom`, chaining, etc.) all apply on the server.

Both sides must share the same `key` and `roomId`.

## Settings reference

The `settings` object is identical for inbound and outbound except for the two
client-only `deviceId*` fields.

| Field | Type | Applies | Notes |
|-------|------|---------|-------|
| `provider` | string | both | `jitsi`, `telemost`, `wbstream`, or `none`. **Required.** |
| `transport` | string | both | `datachannel`, `vp8channel`, `seichannel`, `videochannel`. **Required.** |
| `roomId` | string | both | Room reference for the provider (required unless `provider":"none"`). |
| `key` | string | both | 64 hex chars (32-byte shared key). **Required.** `openssl rand -hex 32`. |
| `dnsServer` | string | both | Resolver used to reach the SFU, e.g. `8.8.8.8:53`. |
| `authToken` | string | both | Optional provider account token (e.g. WbStream). |
| `engine` / `url` / `token` | string | both | Direct engine mode only (`provider":"none"`): `engine` is `livekit`/`goolom`/`jitsi`. |
| `vp8` | object | both | `{ "fps": 30, "batchSize": 64 }` — `vp8channel` tuning. |
| `sei` | object | both | `{ "fps":30, "batchSize":64, "fragmentSize":900, "ackTimeoutMs":2000 }` — `seichannel` tuning. |
| `video` | object | both | `videochannel` tuning: `width,height,fps,bitrate,hw,qrSize,qrRecovery,codec,tileModule,tileRs`. |
| `livenessInterval` / `livenessTimeout` | string | both | Go duration strings (e.g. `"5s"`); empty = defaults. |
| `livenessFailures` | int | both | Missed pongs before reconnect; 0 = default. |
| `maxSessionDuration` | string | both | Rotate the carrier every N (Go duration); empty = never. |
| `deviceId` | string | outbound | Stable client id echoed to the server auth hook. |
| `deviceIdPath` | string | outbound | File to persist an auto-generated device id. |

Unset transport-tuning fields fall back to olcrtc's documented defaults.

### Provider / transport guidance

- Recommended start: `jitsi` + `datachannel`.
- WbStream / Telemost guest flows have no data-channel publish permission — use
  `vp8channel` (main video path), `seichannel`, or `videochannel` there.
- `videochannel` requires `ffmpeg` on the host; `codec":"tile"` requires
  `width:1080, height:1080`.

## JSON usage

See [`example/client.json`](example/client.json) and
[`example/server.json`](example/server.json). Validate with:

```sh
xray run -test -c server.json
```

### wbstream + vp8channel server (excerpt)

```json
{
  "inbounds": [{
    "tag": "olcrtc-in",
    "protocol": "olcrtc",
    "settings": {
      "provider": "wbstream",
      "transport": "vp8channel",
      "roomId": "REPLACE_WITH_ROOM",
      "key": "REPLACE_WITH_64_HEX",
      "dnsServer": "8.8.8.8:53",
      "authToken": "REPLACE_WITH_WBSTREAM_TOKEN",
      "vp8": { "fps": 30, "batchSize": 64 }
    }
  }],
  "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
}
```

## Embedded usage (xray-core as a library)

Build the proxy settings as a `TypedMessage` and hand them to `core.Config`.
Blank-import the proxy (and proxyman/router/dispatcher) so the config types and
the self-driven inbound handler are registered.

```go
import (
    "google.golang.org/protobuf/proto"
    "github.com/xtls/xray-core/common/serial"
    "github.com/xtls/xray-core/core"
    "github.com/xtls/xray-core/proxy/olcrtc"

    _ "github.com/xtls/xray-core/main/distro/all" // registers everything, incl. olcrtc
)

out := &core.OutboundHandlerConfig{
    Tag: "olcrtc-out",
    ProxySettings: serial.ToTypedMessage(&olcrtc.ClientConfig{
        Provider:  "jitsi",
        Transport: "datachannel",
        RoomId:    "https://meet.small-dm.ru/my-room",
        Key:       key64hex,
        DnsServer: "8.8.8.8:53",
    }),
}
// add `out` to core.Config.Outbound, plus a socks/dokodemo inbound, then core.New(cfg).
```

For a server, use `&olcrtc.ServerConfig{...}` in an `InboundHandlerConfig`
(no `ReceiverConfig` port needed) plus a `freedom` outbound for egress.

The lower-level olcrtc library is vendored under
[`olcrtclib/`](olcrtclib) and exposed through
[`olcrtclib/bridge`](olcrtclib/bridge) if you want to drive the tunnel directly
(`bridge.StartClient` / `bridge.RunServer`).

## Caveats

- **TCP only.** olcrtc tunnels stream (TCP) connections; the outbound rejects
  UDP targets. Use another outbound for UDP if needed.
- **Server DNS.** `dnsServer` is used to reach the SFU. Provider auth API calls
  (Telemost/WbStream) use the host's system resolver; Xray's own DNS server is
  not overridden globally by this proxy.
- The `example/*.json` demo room `meet.small-dm.ru` may be down; substitute a
  Jitsi/Telemost/WbStream endpoint that works on your network.

## How it's wired (for maintainers)

- `olcrtclib/` — vendored olcrtc library (import paths rewritten to this module).
  `internal/client` gained `StartTunnel`/`Tunnel.DialContext`; `internal/server`
  gained a `DialHook` so egress can be delegated. `bridge/` is the only exported
  surface `proxy/olcrtc` depends on.
- `config.pb.go` — generated offline (no protoc) from `config.proto` via
  `protoc-gen-go` driven by a hand-built `FileDescriptorProto`.
- Self-driven inbound seam: `proxy.RegisterSelfDrivenInbound` +
  `app/proxyman/inbound/selfdriven.go`; `NewHandler` routes olcrtc there and
  `infra/conf` skips the port requirement for it.
