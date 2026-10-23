# REALITY

## THE NEXT FUTURE

Server side implementation of REALITY protocol, a fork of package tls in latest [Go](https://github.com/golang/go/tree/master/src/crypto/tls).
For client side, please follow https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go.  

TODO List: TODO

## Donation & NFTs

### [Collect a Project X NFT to support the development of Project X!](https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1)

[<img alt="Project X NFT" width="150px" src="https://raw2.seadn.io/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/7fa9ce900fb39b44226348db330e32/8b7fa9ce900fb39b44226348db330e32.svg" />](https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1)

- **ETH/USDT/USDC: `0xDc3Fe44F0f25D13CACb1C4896CD0D321df3146Ee`**
- **Project X NFT: https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1**
- **VLESS NFT: https://opensea.io/collection/vless**
- **REALITY NFT: https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/2**
- **Related links: [VLESS Post-Quantum Encryption](https://github.com/XTLS/Xray-core/pull/5067), [XHTTP: Beyond REALITY](https://github.com/XTLS/Xray-core/discussions/4113), [Announcement of NFTs by Project X](https://github.com/XTLS/Xray-core/discussions/3633)**

## VLESS-XTLS-uTLS-REALITY example for [Xray-core](https://github.com/XTLS/Xray-core)

中文 | [English](README.en.md)

```json5
{
    "inbounds": [ // 服务端入站配置
        {
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "", // 必填，执行 ./xray uuid 生成，或 1-30 字节的字符串
                        "flow": "xtls-rprx-vision" // 选填，若有，客户端必须启用 XTLS
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "target": "example.com:443", // 必填，格式同 VLESS fallbacks 的 dest
                    "xver": 0, // 选填，格式同 VLESS fallbacks 的 xver
                    "serverNames": [ // 必填，客户端可用的 serverName 列表，暂不支持 * 通配符
                        "example.com",
                        "www.example.com"
                    ],
                    "privateKey": "", // 必填，执行 ./xray x25519 生成
                    "minClientVer": "", // 选填，客户端 Xray 最低版本，格式为 x.y.z
                    "maxClientVer": "", // 选填，客户端 Xray 最高版本，格式为 x.y.z
                    "maxTimeDiff": 0, // 选填，允许的最大时间差，单位为毫秒
                    "shortIds": [ // 必填，客户端可用的 shortId 列表，可用于区分不同的客户端
                        "", // 若有此项，客户端 shortId 可为空
                        "0123456789abcdef" // 0 到 f，长度为 2 的倍数，长度上限为 16
                    ],
                    "mldsa65Seed": "", // 选填，执行 ./xray mldsa65 生成，对证书进行抗量子的额外签名
                    // 下列两个 limit 为选填，可对未通过验证的回落连接限速，bytesPerSec 默认为 0 即不启用
                    // 回落限速是一种特征，不建议启用，如果您是面板/一键脚本开发者，务必让这些参数随机化
                    "limitFallbackUpload": {
                        "afterBytes": 0, // 传输指定字节后开始限速
                        "bytesPerSec": 0, // 基准速率（字节/秒）
                        "burstBytesPerSec": 0 // 突发速率（字节/秒），大于 bytesPerSec 时生效
                    },
                    "limitFallbackDownload": {
                        "afterBytes": 0, // 传输指定字节后开始限速
                        "bytesPerSec": 0, // 基准速率（字节/秒）
                        "burstBytesPerSec": 0 // 突发速率（字节/秒），大于 bytesPerSec 时生效
                    }
                }
            }
        }
    ]
}
```

若用 REALITY 取代 TLS，**可消除服务端 TLS 指纹特征**，仍有前向保密性等，**且证书链攻击无效，安全性超越常规 TLS**  
**可以指向别人的网站**，无需自己买域名、配置 TLS 服务端，更方便，**实现向中间人呈现指定 SNI 的全程真实 TLS**  

通常代理用途，目标网站最低标准：**国外网站，支持 TLSv1.3 与 H2，域名非跳转用**（主域名可能被用于跳转到 www）  
加分项：IP 相近（更像，且延迟低），Server Hello 后的握手消息一起加密（如 dl.google.com），有 OCSP Stapling  
配置加分项：**禁回国流量，TCP/80、UDP/443 也转发**（REALITY 对外表现即为端口转发，目标 IP 冷门或许更好）  

**REALITY 也可以搭配 XTLS 以外的代理协议使用**，但不建议这样做，因为它们存在明显且已被针对的 TLS in TLS 特征  
REALITY 的下一个主要目标是“**预先构建模式**”，即提前采集目标网站特征，XTLS 的下一个主要目标是 **0-RTT**  

```json5
{
    "outbounds": [ // 客户端出站配置
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "", // 服务端的域名或 IP
                        "port": 443,
                        "users": [
                            {
                                "id": "", // 与服务端一致
                                "flow": "xtls-rprx-vision", // 与服务端一致
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 选填，使用 uTLS 库模拟客户端 TLS 指纹，默认 chrome
                    "serverName": "", // 服务端 serverNames 之一
                    "password": "", // 服务端私钥生成的公钥，对客户端来说就是密码
                    "shortId": "", // 服务端 shortIds 之一
                    "mldsa65Verify": "", // 选填，服务端 mldsa65Seed 生成的公钥，对证书进行抗量子的额外验证
                    "spiderX": "" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
        }
    ]
}
```

REALITY 客户端应当收到由“**临时认证密钥**”签发的“**临时可信证书**”，但以下三种情况会收到目标网站的真证书：

1. REALITY 服务端拒绝了客户端的 Client Hello，流量被导入目标网站
2. 客户端的 Client Hello 被中间人重定向至目标网站
3. 中间人攻击，可能是目标网站帮忙，也可能是证书链攻击

REALITY 客户端可以完美区分临时可信证书、真证书、无效证书，并决定下一步动作：

1. 收到临时可信证书时，连接可用，一切如常
2. 收到真证书时，进入爬虫模式
3. 收到无效证书时，TLS alert，断开连接

## Stargazers over time

[![Stargazers over time](https://starchart.cc/XTLS/REALITY.svg)](https://starchart.cc/XTLS/REALITY)
