# Project X

[Project X](https://github.com/XTLS) originates from XTLS protocol, provides a set of network tools such as [Xray-core](https://github.com/XTLS/Xray-core).

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## Document

[Project X](https://xtls.github.io/Xray-docs-next/config/)

## Installation

- Linux Script
  - [Xray-script](https://github.com/kirin10000/Xray-script) (Official)
- Docker
  - [teddysun/xray](https://hub.docker.com/r/teddysun/xray)
- One Click
  - [Xray-install](https://github.com/XTLS/Xray-install)
  - [Xray_bash_onekey](https://github.com/hello-yunshu/Xray_bash_onekey)
  - [v2ray-agent](https://github.com/mack-a/v2ray-agent)
  - [Xray-yes](https://github.com/jiuqi9997/Xray-yes) (Lack of maintenance)
  - [Xray_onekey](https://github.com/wulabing/Xray_onekey) (Lack of maintenance)
  - [ProxySU](https://github.com/proxysu/ProxySU) (Lack of maintenance)
- Magisk
  - [Xray4Magisk](https://github.com/CerteKim/Xray4Magisk)
  - [Xray_For_Magisk](https://github.com/E7KMbb/Xray_For_Magisk) (Lack of maintenance)
- Homebrew
  - `brew install xray`
  - [(Tap) Repository 0](https://github.com/N4FA/homebrew-xray)
- Tutorial
  - [Xray Vision tutorial](https://github.com/chika0801/Xray-install)
  - [Xray REALITY tutorial](https://cscot.pages.dev/2023/03/02/Xray-REALITY-tutorial/)

## Contributing
[Code Of Conduct](https://github.com/XTLS/Xray-core/blob/main/CODE_OF_CONDUCT.md)

## Usage

[Xray-examples](https://github.com/XTLS/Xray-examples) / [All-in-One-fallbacks-Nginx](https://github.com/XTLS/Xray-examples/tree/main/All-in-One-fallbacks-Nginx)

[chika0801's examples](https://github.com/chika0801/Xray-examples)

[lxhao61's examples](https://github.com/lxhao61/integrated-examples)

## GUI Clients

- Use Xray-core
  - Windows
    - [v2rayN](https://github.com/2dust/v2rayN)
  - Android
    - [v2rayNG](https://github.com/2dust/v2rayNG)
- Use [Clash Meta kernel](https://github.com/MetaCubeX/Clash.Meta)
  - Windows
    - [Clash Verge](https://github.com/zzzgydi/clash-verge)
    - [clashN](https://github.com/2dust/clashN)
  - Android
    - [Clash Meta For Android](https://github.com/MetaCubeX/ClashMetaForAndroid)
  - macOS
    - [Clash Verge](https://github.com/zzzgydi/clash-verge)
  - Linux
    - [Clash Verge](https://github.com/zzzgydi/clash-verge)
- Use [sing-box](https://github.com/SagerNet/sing-box)
  - Windows
    - [NekoRay](https://github.com/MatsuriDayo/nekoray)
  - Android
    - [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid)
- OpenWrt
  - [ShadowSocksR Plus+](https://github.com/fw876/helloworld)
  - [PassWall](https://github.com/xiaorouji/openwrt-passwall)
  - [PassWall 2](https://github.com/xiaorouji/openwrt-passwall2)
  - [HelloWorld](https://github.com/jerrykuku/luci-app-vssr)
  - [luci-app-xray](https://github.com/yichya/luci-app-xray)
- iOS & macOS
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [Wings X](https://apps.apple.com/app/wings-x-client/id6446119727)
  - [Stash](https://apps.apple.com/app/stash/id1596063349)
- macOS
  - [V2RayXS](https://github.com/tzmax/V2RayXS)

## Credits

This repo relies on the following third-party projects:

- Special thanks:
  - [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- In production:
  - [ghodss/yaml](https://github.com/ghodss/yaml)
  - [gorilla/websocket](https://github.com/gorilla/websocket)
  - [quic-go/quic-go](https://github.com/quic-go/quic-go)
  - [pelletier/go-toml](https://github.com/pelletier/go-toml)
  - [pires/go-proxyproto](https://github.com/pires/go-proxyproto)
  - [refraction-networking/utls](https://github.com/refraction-networking/utls)
  - [seiflotfy/cuckoofilter](https://github.com/seiflotfy/cuckoofilter)
  - [google/starlark-go](https://github.com/google/starlark-go)
- For testing only:
  - [miekg/dns](https://github.com/miekg/dns)
  - [stretchr/testify](https://github.com/stretchr/testify)
  - [h12w/socks](https://github.com/h12w/socks)

## Compilation

### Windows

```bash
go build -o xray.exe -trimpath -ldflags "-s -w -buildid=" ./main
```

### Linux / macOS

```bash
go build -o xray -trimpath -ldflags "-s -w -buildid=" ./main
```

## Telegram

[Project X](https://t.me/projectXray)

[Project X Channel](https://t.me/projectXtls)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/XTLS/Xray-core.svg)](https://starchart.cc/XTLS/Xray-core)
