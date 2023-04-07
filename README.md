This repo includes personal hacks that allow for easier configuration of complex setups, such as multiple inbounds/outbounds, multiple IPs, _etc_.

###### Already implemented hacks:

1. Accepts 'json5' as valid config file extension

&ensp;&ensp;&ensp;&ensp;Many editors will only provide json5 syntax highlighting for '.json5' file.

2. Accepts special 'sendThrough' value of '255.255.255.255' to use the same IP that received the inbound connection

&ensp;&ensp;&ensp;&ensp;This is useful for machines with multiple IPs. Default outgoing IP will be used instead if inbound was received on loopback interface or through an IP in different family.

3. Allows templating in inbound and outbound configurations

&ensp;&ensp;&ensp;&ensp;By specifying a "template" key to reference the "tag" of an inbound/outbound defined earlier, all configurations of the template inbound/outbound will be inherited first and then only specified configurations will be used to override corresponding settings in the template. Templates can be cascaded. This makes writing configs for similar inbounds/outbounds much easier.

```json5
"outbounds":
[
  { "tag": "s5-1", "protocol": "socks",
    "settings": {
      "servers": [
        { "address": "1.2.3.4", "port": 1080
          "users": [{
            "user": "test user",
            "pass": "test pass",
            "level": 0
          }]
        }
      ]
    }
  },
  { "tag": "s5-2", "template": "s5-1",
    "settings": {"servers": [{"address": "4.3.2.1"}]}
  },
  { "tag": "s5-3", "template": "s5-2",
    "settings": {"servers": [{"port": 1081}]}
  }
]
```
&ensp;&ensp;&ensp;&ensp;In the example above, the "s5-2" outbound differs with "s5-1" only in server address, while "s5-3" only differs with "s5-2" in server port.

4. Adds special "@" prefix for "outbound" setting in routing rule

&ensp;&ensp;&ensp;&ensp;This allows automatic searching for outbound tag that matches inbound tag ("@inboundTag"), user IP ("@sourceIP"), local address ("@incomingAddr") and port ("@incomingPort") that received inbound connection, or user email ("@user"). Multiple searching rules can be concatenated using ";", and the first one with a matching result will be used.

```json5
"routing":
{
  "rules": [
    ...
    { "outboundTag": "@incomingAddr;user",      "type": "field" }
  ]
}
```
&ensp;&ensp;&ensp;&ensp;In the example above, routing will first try to find outbound whose tag matches user IP address; and if no match could be found, use user email; and if still no match, use default outbound. Since rule starting with "@" will always match any request, even if no outbound satisfying the request could be found later, such a rule only makes sense when used as the last rule.

___
# Project X

[Project X](https://github.com/XTLS) originates from XTLS protocol, providing a set of network tools such as [Xray-core](https://github.com/XTLS/Xray-core) and [REALITY](https://github.com/XTLS/REALITY).

[README](https://github.com/XTLS/Xray-core#readme) is open, so feel free to submit your project [here](https://github.com/XTLS/Xray-core/pulls).

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## Documentation

[Project X Official Website](https://xtls.github.io)

## Telegram

[Project X](https://t.me/projectXray)

[Project X Channel](https://t.me/projectXtls)

## Installation

- Linux Script
  - [XTLS/Xray-install](https://github.com/XTLS/Xray-install)
- Docker
  - [teddysun/xray](https://hub.docker.com/r/teddysun/xray)
- Web Panel
  - [X-UI](https://github.com/FranzKafkaYu/x-ui), [X-UI-English](https://github.com/NidukaAkalanka/x-ui-english), [3X-UI](https://github.com/MHSanaei/3x-ui), [X-UI](https://github.com/alireza0/x-ui), [X-UI](https://github.com/diditra/x-ui)
  - [Hiddify](https://github.com/hiddify/hiddify-config)
  - [Marzban](https://github.com/Gozargah/Marzban)
- One Click
  - [Xray-script](https://github.com/kirin10000/Xray-script), [Xray-script](https://github.com/zxcvos/Xray-script), [xray_script](https://github.com/tdjnodj/xray_script)
  - [XTool](https://github.com/LordPenguin666/XTool), [Xray_bash_onekey](https://github.com/hello-yunshu/Xray_bash_onekey), [xray-reality](https://github.com/sajjaddg/xray-reality)
  - [v2ray-agent](https://github.com/mack-a/v2ray-agent), [Xray_onekey](https://github.com/wulabing/Xray_onekey), [ProxySU](https://github.com/proxysu/ProxySU)
- Magisk
  - [Xray4Magisk](https://github.com/CerteKim/Xray4Magisk)
  - [Xray_For_Magisk](https://github.com/E7KMbb/Xray_For_Magisk)
- Homebrew
  - `brew install xray`
  - [(Tap) Repository 0](https://github.com/N4FA/homebrew-xray)

## Usage

- Example
  - [VLESS-XTLS-uTLS-REALITY](https://github.com/XTLS/REALITY#readme)
  - [VLESS-TCP-XTLS-Vision](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision)
  - [All-in-One-fallbacks-Nginx](https://github.com/XTLS/Xray-examples/tree/main/All-in-One-fallbacks-Nginx)
- Xray-examples
  - [XTLS/Xray-examples](https://github.com/XTLS/Xray-examples)
  - [chika0801/Xray-examples](https://github.com/chika0801/Xray-examples)
  - [lxhao61/integrated-examples](https://github.com/lxhao61/integrated-examples)
- Tutorial
  - [XTLS Vision](https://github.com/chika0801/Xray-install)
  - [REALITY (English)](https://cscot.pages.dev/2023/03/02/Xray-REALITY-tutorial/)

## GUI Clients

- OpenWrt
  - [PassWall](https://github.com/xiaorouji/openwrt-passwall), [PassWall 2](https://github.com/xiaorouji/openwrt-passwall2)
  - [ShadowSocksR Plus+](https://github.com/fw876/helloworld)
  - [luci-app-xray](https://github.com/yichya/luci-app-xray) ([openwrt-xray](https://github.com/yichya/openwrt-xray))
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [Invisible Man - Xray](https://github.com/InvisibleManVPN/InvisibleMan-XRayClient)
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNG)
  - [X-flutter](https://github.com/XTLS/X-flutter)
- iOS & macOS arm64
  - [Mango](https://github.com/daemooon/Mango)
  - [Wings X](https://apps.apple.com/app/wings-x/id6446119727)
- macOS arm64 & x64
  - [V2RayXS](https://github.com/tzmax/V2RayXS)
  - [Wings X](https://apps.apple.com/app/wings-x/id6446119727)

## Others that support VLESS, XTLS, REALITY, XUDP, PLUX...

- iOS & macOS arm64
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [Stash](https://apps.apple.com/app/stash/id1596063349)
- API Wrapper
  - [xtlsapi](https://github.com/hiddify/xtlsapi)
- [XrayR](https://github.com/XrayR-project/XrayR)
  - [XrayR-release](https://github.com/XrayR-project/XrayR-release)
  - [XrayR-V2Board](https://github.com/missuo/XrayR-V2Board)
- [Clash.Meta](https://github.com/MetaCubeX/Clash.Meta)
  - [Clash Verge](https://github.com/zzzgydi/clash-verge)
  - [clashN](https://github.com/2dust/clashN)
  - [Clash Meta for Android](https://github.com/MetaCubeX/ClashMetaForAndroid)
  - [meta_for_ios](https://t.me/meta_for_ios)
- [sing-box](https://github.com/SagerNet/sing-box)
  - [installReality](https://github.com/BoxXt/installReality)
  - [sbox-reality](https://github.com/Misaka-blog/sbox-reality)
  - [sing-box-for-ios](https://github.com/SagerNet/sing-box-for-ios)

## Contributing

[Code of Conduct](https://github.com/XTLS/Xray-core/blob/main/CODE_OF_CONDUCT.md)

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

## Stargazers over time

[![Stargazers over time](https://starchart.cc/XTLS/Xray-core.svg)](https://starchart.cc/XTLS/Xray-core)
