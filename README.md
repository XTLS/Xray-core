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

[Project X](https://github.com/XTLS) originates from XTLS protocol, provides a set of network tools such as [Xray-core](https://github.com/XTLS/Xray-core).

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## Installation

- Linux Script
  - [Xray-install](https://github.com/XTLS/Xray-install)
  - [Xray-script](https://github.com/kirin10000/Xray-script)
- Docker
  - [teddysun/xray](https://hub.docker.com/r/teddysun/xray)
- One Click
  - [ProxySU](https://github.com/proxysu/ProxySU)
  - [v2ray-agent](https://github.com/mack-a/v2ray-agent)
  - [Xray-yes](https://github.com/jiuqi9997/Xray-yes)
  - [Xray_onekey](https://github.com/wulabing/Xray_onekey)
- Magisk
  - [Xray4Magisk](https://github.com/CerteKim/Xray4Magisk)
  - [Xray_For_Magisk](https://github.com/E7KMbb/Xray_For_Magisk)
- Homebrew
  - `brew install xray`
  - [(Tap) Repository 0](https://github.com/N4FA/homebrew-xray)
  - [(Tap) Repository 1](https://github.com/xiruizhao/homebrew-xray)

## Contributing
[Code Of Conduct](https://github.com/XTLS/Xray-core/blob/main/CODE_OF_CONDUCT.md)

## Usage

[Xray-examples](https://github.com/XTLS/Xray-examples) / [VLESS-TCP-XTLS-WHATEVER](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-WHATEVER)

## GUI Clients

- OpenWrt
  - [PassWall](https://github.com/xiaorouji/openwrt-passwall)
  - [Hello World](https://github.com/jerrykuku/luci-app-vssr)
  - [ShadowSocksR Plus+](https://github.com/fw876/helloworld)
  - [luci-app-xray](https://github.com/yichya/luci-app-xray) ([openwrt-xray](https://github.com/yichya/openwrt-xray))
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [Qv2ray](https://github.com/Qv2ray/Qv2ray) (This project had been archived and currently inactive)
  - [Netch (NetFilter & TUN/TAP)](https://github.com/NetchX/Netch) (This project had been archived and currently inactive)
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNG)
  - [Kitsunebi](https://github.com/rurirei/Kitsunebi/tree/release_xtls)
- iOS & macOS (with M1 chip)
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [Stash](https://apps.apple.com/app/stash/id1596063349)
- macOS (Intel chip & M1 chip)
  - [Qv2ray](https://github.com/Qv2ray/Qv2ray) (This project had been archived and currently inactive)
  - [V2RayXS](https://github.com/tzmax/V2RayXS)

## Credits

This repo relies on the following third-party projects:

- Special thanks:
  - [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- In production:
  - [ghodss/yaml](https://github.com/ghodss/yaml)
  - [gorilla/websocket](https://github.com/gorilla/websocket)
  - [lucas-clemente/quic-go](https://github.com/lucas-clemente/quic-go)
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
