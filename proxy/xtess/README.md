# XTESS 协议使用与配置

XTESS 是一个基于 Xray 协议栈实现的传输/代理协议实现，支持入站（服务端）与出站（客户端）两种工作模式，配置方式与 Xray 其它协议（如 VLESS/VMess/Trojan）保持一致：通过 `inbounds[].protocol` / `outbounds[].protocol` 选择协议，通过 `settings` 填写协议参数，通过 `streamSettings` 选择底层传输（tcp/ws/grpc/tls/reality 等）。

本文档面向 `MoreRay-core` 的实现，代码位于：
- 协议实现：[proxy/xtess](file:///d:/CoreDev/MoreRay/MoreRay-core/proxy/xtess)
- JSON 配置解析：[infra/conf/xtess.go](file:///d:/CoreDev/MoreRay/MoreRay-core/infra/conf/xtess.go)
- 协议名映射（`"protocol": "xtess"`）：[infra/conf/xray.go](file:///d:/CoreDev/MoreRay/MoreRay-core/infra/conf/xray.go)
- `xtessenc` 命令：[main/commands/all/xtessenc.go](file:///d:/CoreDev/MoreRay/MoreRay-core/main/commands/all/xtessenc.go)

## 1. 快速开始（本机真实联调）

仓库内已提供一套可直接运行的本机联调配置（不依赖 geoip/geosite 数据）：
- 服务端：[_xtess_test/server.json](file:///d:/CoreDev/MoreRay/MoreRay-core/_xtess_test/server.json)
- 客户端：[_xtess_test/client.json](file:///d:/CoreDev/MoreRay/MoreRay-core/_xtess_test/client.json)

联调拓扑如下：
- 本机 HTTP 测试服务：`127.0.0.1:18080`
- XTESS 服务端：`127.0.0.1:12345`
- XTESS 客户端 SOCKS5 入站：`127.0.0.1:10809`
- 测试命令：通过 SOCKS5 访问本机 HTTP

### 1.1 启动本机 HTTP 测试服务

PowerShell 示例（返回固定文本 `ok`）：

```powershell
$ErrorActionPreference='Stop'
$listener=[System.Net.HttpListener]::new()
$listener.Prefixes.Add('http://127.0.0.1:18080/')
$listener.Start()
Write-Host 'HTTP test server: http://127.0.0.1:18080/'
while($listener.IsListening){
  $ctx=$listener.GetContext()
  $bytes=[Text.Encoding]::UTF8.GetBytes('ok')
  $ctx.Response.StatusCode=200
  $ctx.Response.ContentType='text/plain'
  $ctx.Response.ContentLength64=$bytes.Length
  $ctx.Response.OutputStream.Write($bytes,0,$bytes.Length)
  $ctx.Response.OutputStream.Close()
}
```

### 1.2 启动 XTESS 服务端与客户端

在 `MoreRay-core` 根目录执行：

```powershell
go run .\main -c .\_xtess_test\server.json
```

另开一个终端执行：

```powershell
go run .\main -c .\_xtess_test\client.json
```

### 1.3 发起真实请求验证链路

PowerShell 里请使用 `curl.exe`（避免被别名到 `Invoke-WebRequest`）：

```powershell
curl.exe -v --socks5-hostname 127.0.0.1:10809 http://127.0.0.1:18080/
```

预期响应 body 为：

```text
ok
```

## 2. 协议概览

### 2.1 角色与基本数据流

- 服务端（入站 `xtess`）：接受客户端连接，解析 XTESS 请求头，认证用户后把流量交给下游出站（通常是 `freedom`）转发到真实目的地。
- 客户端（出站 `xtess`）：按路由规则选择 XTESS 出站，把原始目标（Address/Port/Network）编码进 XTESS 请求头，经由底层传输（tcp/ws/grpc/tls/reality 等）发往服务端。

### 2.2 核心特性（实现相关）

以下行为来自实现细节，属于协议特性的一部分：
- 请求头版本：`Version = 2`（见 [proxy/xtess/encoding/encoding.go](file:///d:/CoreDev/MoreRay/MoreRay-core/proxy/xtess/encoding/encoding.go)）。
- 域名“伪装”：当目标为域名时，会把请求头里的域名替换为固定域名（实现中为 `baidu.com`），真实域名会被 XOR 后再 base64 放在头部尾段并携带长度。
- 可选握手加密（XTESS Encryption）：可通过 `decryption` / `encryption` 启用基于 `mlkem768 + x25519` 组合的握手与 0-RTT/1-RTT 票据机制（详见第 6 节）。
- 反向（Reverse / RVS）与 Mux 命令：实现中包含 `RequestCommandMux` / `RequestCommandRvs` 分支（详见第 7 节）。

## 3. 基本配置结构

XTESS 的配置位置与 Xray 其它协议一致：

```json
{
  "inbounds": [
    {
      "protocol": "xtess",
      "settings": { },
      "streamSettings": { }
    }
  ],
  "outbounds": [
    {
      "protocol": "xtess",
      "settings": { },
      "streamSettings": { }
    }
  ]
}
```

说明：
- `protocol` 固定写 `"xtess"`。
- `settings` 的具体字段见第 4（入站）与第 5（出站）节。
- `streamSettings` 仍然使用通用传输层配置（tcp/ws/grpc/httpUpgrade/tls/reality 等），XTESS 不额外新增 `streamSettings` 字段。

## 4. 入站（服务端）配置：`inbounds[].settings`

入站的 JSON 结构由 [infra/conf/xtess.go](file:///d:/CoreDev/MoreRay/MoreRay-core/infra/conf/xtess.go) 中 `XTessInboundConfig` 解析构建，对应 PB 配置为 [proxy/xtess/inbound/config.pb.go](file:///d:/CoreDev/MoreRay/MoreRay-core/proxy/xtess/inbound/config.pb.go)。

### 4.1 字段说明

- `clients`：数组，定义允许连接的用户列表。
  - 每个元素必须包含：
    - `id`：UUID 字符串（必填）。
  - 可选：
    - `flow`：服务端对该用户允许的流控/模式（详见 4.2）。
    - `reverse`：允许该用户建立反向（详见第 7 节）。
  - 注意：入站用户里不允许出现 `encryption`（这是客户端出站用户才允许的字段），否则配置解析会报错。
- `flow`：入站的默认 flow，用于给未显式设置 `clients[].flow` 的用户填默认值。
- `decryption`：服务端握手解密参数（详见第 6 节）。
- `fallbacks`：fallback 列表（详见 4.3）。

### 4.2 `flow` 取值与约束（入站）

入站 `flow` 与 `clients[].flow` 支持的值：
- `""`：空字符串
- `"none"`：会被归一化为 `""`
- `"xtls-rprx-vision"`

不支持其它值。

### 4.3 `fallbacks`（入站可选）

`fallbacks` 用于在“无法识别为 XTESS”或需要回落时，将连接转发到其它目标（例如回落到本机某端口或 unix socket）。

每个 fallback 可包含：
- `name`：匹配 SNI/ServerName（空为默认）。
- `alpn`：匹配 ALPN（空为默认）。
- `path`：匹配 HTTP path（空为默认）。
- `dest`：目标（可写端口号、`host:port`、或 unix/serve 特殊值）。
- `type`：`tcp` / `unix` / `serve`（有些情况下可由 `dest` 推断）。
- `xver`：PROXY protocol 版本（0/1/2）。

重要限制：
- 当 `decryption` 为非 `"none"` 的有效值时，不能与 `fallbacks` 同时使用（配置会被拒绝）。

## 5. 出站（客户端）配置：`outbounds[].settings`

出站的 JSON 结构由 [infra/conf/xtess.go](file:///d:/CoreDev/MoreRay/MoreRay-core/infra/conf/xtess.go) 中 `XTessOutboundConfig` 解析构建，对应 PB 配置为 [proxy/xtess/outbound/config.pb.go](file:///d:/CoreDev/MoreRay/MoreRay-core/proxy/xtess/outbound/config.pb.go)。

### 5.1 标准写法：`vnext`

```json
{
  "protocol": "xtess",
  "settings": {
    "vnext": [
      {
        "address": "server.example.com",
        "port": 443,
        "users": [
          {
            "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57",
            "encryption": "none",
            "flow": "xtls-rprx-vision"
          }
        ]
      }
    ]
  }
}
```

约束：
- `vnext` 必须且只能包含 1 个元素。
- `users` 必须且只能包含 1 个元素。

### 5.2 出站用户字段

出站 `users[0]` 支持字段：
- `id`：UUID 字符串（必填）。
- `encryption`：握手加密参数（必填，至少填 `"none"`）（详见第 6 节）。
- `flow`：（可选）详见 5.3。
- `reverse.tag`：（可选）用于启用反向（详见第 7 节）。

### 5.3 `flow` 取值与约束（出站）

出站用户 `flow` 支持的值：
- `""`（默认）
- `"xtls-rprx-vision"`
- `"xtls-rprx-vision-udp443"`

注意：
- 出站不接受 `"none"` 作为 `flow` 值（与入站不同），如果需要“无 flow”，请省略该字段或使用空字符串。

## 6. XTESS Encryption（握手加密）与 `xtessenc`

XTESS 支持可选的握手加密机制：通过在服务端入站配置 `decryption`、在客户端出站用户配置 `encryption` 来启用。

### 6.1 `xtessenc` 命令

运行：

```bash
xray xtessenc
```

输出会包含两组“认证材料”（二选一，不要混用）：
- Authentication: X25519（非 PQ）
- Authentication: ML-KEM-768（PQ）

并给出两条字符串：
- `"decryption": "..."`：用于服务端入站 `settings.decryption`
- `"encryption": "..."`：用于客户端出站 `users[0].encryption`

实现见：[main/commands/all/xtessenc.go](file:///d:/CoreDev/MoreRay/MoreRay-core/main/commands/all/xtessenc.go)

### 6.2 `decryption` 格式（服务端）

服务端 `decryption` 支持：
- `"none"`：关闭握手加密（最简单、最适合联调）。
- 点分格式（内部会解析）：`mlkem768x25519plus.<mode>.<seconds>.<keys...>`

其中：
- `<mode>`：`native` / `xorpub` / `random`
- `<seconds>`：如 `600s`，也支持区间 `600-1200s`（表示票据有效期范围）
- `<keys...>`：base64url（raw）编码的 key 材料；字符串中允许插入较短的 padding 字段段落（实现会解析）

限制：
- `decryption != "none"` 时不能配置 `fallbacks`。

### 6.3 `encryption` 格式（客户端）

客户端出站用户 `encryption` 支持：
- `"none"`：关闭握手加密。
- 点分格式：`mlkem768x25519plus.<mode>.<0rtt|1rtt>.<keys...>`

其中：
- `<0rtt|1rtt>` 用于指示是否启用 0-RTT 票据尝试。

### 6.4 最小加密示例

- 服务端（入站）：
  - `settings.decryption = "<xtessenc 输出的 decryption>"`
- 客户端（出站用户）：
  - `users[0].encryption = "<xtessenc 输出的 encryption>"`

其它字段（`id`、`streamSettings`）照常填写。

## 7. Mux / Reverse（RVS）说明

XTESS 实现中存在两类“命令目标”：
- Mux：`v1.mux.cool`（内部会映射为 `RequestCommandMux`）
- RVS：`v1.rvs.cool`（内部会映射为 `RequestCommandRvs`）

### 7.1 Reverse 的配置方式

Reverse 通过用户级别启用：
- 客户端出站用户：

```json
{
  "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57",
  "encryption": "none",
  "reverse": { "tag": "some-outbound-tag" }
}
```

- 服务端入站用户允许 reverse：
  - `clients[].reverse.tag` 不能为空（否则配置解析会失败）。

Reverse 的实现点：
- 入站处理：[proxy/xtess/inbound/inbound.go](file:///d:/CoreDev/MoreRay/MoreRay-core/proxy/xtess/inbound/inbound.go)
- 出站桥接：[proxy/xtess/outbound/outbound.go](file:///d:/CoreDev/MoreRay/MoreRay-core/proxy/xtess/outbound/outbound.go)

如果你不需要反向功能，可以完全忽略本节。

## 8. streamSettings（传输层）建议

XTESS 不绑定特定传输，通常搭配以下任一方式：
- TCP：最简单，适合本机/内网联调。
- TLS/REALITY：适合公网部署（需按你现有部署方式配置通用 `streamSettings`）。
- WS/GRPC：适合需要中转/伪装的场景（同样由通用 `streamSettings` 负责）。

建议联调顺序：
1) 先用纯 TCP + `encryption: "none"` 跑通功能链路。
2) 再逐步加入 TLS/REALITY。
3) 最后再启用 `xtessenc` 的 `decryption/encryption`。

## 9. 常见错误与排查

### 9.1 出站 `flow` 写成 `"none"`

症状：加载配置时报 `XTESS users: "flow" doesn't support "none"`。

原因：出站支持 `""/xtls-rprx-vision/xtls-rprx-vision-udp443`，不支持 `"none"`。

解决：删除 `flow` 字段或写空字符串。

### 9.2 入站用户里写了 `encryption`

症状：加载配置时报 `XTESS clients: "encryption" should not be in inbound settings`。

原因：握手加密的客户端参数在出站用户里，服务端只使用 `settings.decryption`。

解决：从 `clients[]` 中移除 `encryption`，把服务端参数放到 `decryption`。

### 9.3 `decryption` 与 `fallbacks` 同时配置

症状：加载配置时报 `XTESS settings: "fallbacks" can not be used together with "decryption"`。

解决：二选一；联调阶段建议先用 `decryption: "none"` 并关闭 fallback。

### 9.4 本机 curl 测试不走 SOCKS

PowerShell 中 `curl` 可能是 `Invoke-WebRequest` 别名。

解决：使用 `curl.exe`：

```powershell
curl.exe -v --socks5-hostname 127.0.0.1:10809 http://127.0.0.1:18080/
```

