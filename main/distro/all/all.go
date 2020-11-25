package all

import (
	// The following are necessary as they register handlers in their init functions.

	// Required features. Can't remove unless there is replacements.
	_ "github.com/xtls/xray-core/v1/app/dispatcher"
	_ "github.com/xtls/xray-core/v1/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/v1/app/proxyman/outbound"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/xtls/xray-core/v1/app/commander"
	_ "github.com/xtls/xray-core/v1/app/log/command"
	_ "github.com/xtls/xray-core/v1/app/proxyman/command"
	_ "github.com/xtls/xray-core/v1/app/stats/command"

	// Other optional features.
	_ "github.com/xtls/xray-core/v1/app/dns"
	_ "github.com/xtls/xray-core/v1/app/log"
	_ "github.com/xtls/xray-core/v1/app/policy"
	_ "github.com/xtls/xray-core/v1/app/reverse"
	_ "github.com/xtls/xray-core/v1/app/router"
	_ "github.com/xtls/xray-core/v1/app/stats"

	// Inbound and outbound proxies.
	_ "github.com/xtls/xray-core/v1/proxy/blackhole"
	_ "github.com/xtls/xray-core/v1/proxy/dns"
	_ "github.com/xtls/xray-core/v1/proxy/dokodemo"
	_ "github.com/xtls/xray-core/v1/proxy/freedom"
	_ "github.com/xtls/xray-core/v1/proxy/http"
	_ "github.com/xtls/xray-core/v1/proxy/mtproto"
	_ "github.com/xtls/xray-core/v1/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/v1/proxy/socks"
	_ "github.com/xtls/xray-core/v1/proxy/trojan"
	_ "github.com/xtls/xray-core/v1/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/v1/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/v1/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/v1/proxy/vmess/outbound"

	// Transports
	_ "github.com/xtls/xray-core/v1/transport/internet/domainsocket"
	_ "github.com/xtls/xray-core/v1/transport/internet/http"
	_ "github.com/xtls/xray-core/v1/transport/internet/kcp"
	_ "github.com/xtls/xray-core/v1/transport/internet/quic"
	_ "github.com/xtls/xray-core/v1/transport/internet/tcp"
	_ "github.com/xtls/xray-core/v1/transport/internet/tls"
	_ "github.com/xtls/xray-core/v1/transport/internet/udp"
	_ "github.com/xtls/xray-core/v1/transport/internet/websocket"
	_ "github.com/xtls/xray-core/v1/transport/internet/xtls"

	// Transport headers
	_ "github.com/xtls/xray-core/v1/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/v1/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/v1/transport/internet/headers/srtp"
	_ "github.com/xtls/xray-core/v1/transport/internet/headers/tls"
	_ "github.com/xtls/xray-core/v1/transport/internet/headers/utp"
	_ "github.com/xtls/xray-core/v1/transport/internet/headers/wechat"
	_ "github.com/xtls/xray-core/v1/transport/internet/headers/wireguard"

	// JSON config support. Choose only one from the two below.
	// The following line loads JSON from xctl
	// _ "github.com/xtls/xray-core/v1/main/json"
	// The following line loads JSON internally
	_ "github.com/xtls/xray-core/v1/main/jsonem"

	// Load config from file or http(s)
	_ "github.com/xtls/xray-core/v1/main/confloader/external"

	// commands
	_ "github.com/xtls/xray-core/v1/main/commands/all"
)
