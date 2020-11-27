# Project X

[Project X](https://github.com/XTLS) originates from XTLS protocol, provides a set of network tools such as [Xray-core](https://github.com/XTLS/Xray-core) and [Xray-flutter](https://github.com/XTLS/Xray-flutter).

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## Installation

- Linux Script
  - [Xray-install](https://github.com/XTLS/Xray-install)
  - [Xray-script](https://github.com/kirin10000/Xray-script)
- Docker
  - [teddysun/xray](https://hub.docker.com/r/teddysun/xray)
  - [charlieethan](https://github.com/users/charlieethan/packages/container/package/xray)
- One Click
  - [ProxySU](https://github.com/proxysu/ProxySU)
  - [v2ray-agent](https://github.com/mack-a/v2ray-agent)

## Usage

[Xray-examples](https://github.com/XTLS/Xray-examples) / [VLESS-TCP-XTLS-WHATEVER](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-WHATEVER)

## Credits

This repo relies on the following third-party projects:

- Special thanks:
  - [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- In production:
  - [gorilla/websocket](https://github.com/gorilla/websocket)
  - [lucas-clemente/quic-go](https://github.com/lucas-clemente/quic-go)
  - [pires/go-proxyproto](https://github.com/pires/go-proxyproto)
  - [seiflotfy/cuckoofilter](https://github.com/seiflotfy/cuckoofilter)
  - [google/starlark-go](https://github.com/google/starlark-go)
- For testing only:
  - [miekg/dns](https://github.com/miekg/dns)
  - [h12w/socks](https://github.com/h12w/socks)

## Compilation

### Windows

```
go build -o xray.exe -trimpath -ldflags "-s -w -buildid=" ./main
```

### Linux / macOS

```
go build -o xray -trimpath -ldflags "-s -w -buildid=" ./main
```

## Telegram

[Project X](https://t.me/projectXray)

[Project X Channel](https://t.me/projectXtls)
