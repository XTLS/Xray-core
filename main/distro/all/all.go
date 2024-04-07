package all

import (
	// The following are necessary as they register handlers in their init functions.

	// Mandatory features. Can't remove unless there are replacements.
	_ "github.com/GFW-knocker/Xray-core/app/dispatcher"
	_ "github.com/GFW-knocker/Xray-core/app/proxyman/inbound"
	_ "github.com/GFW-knocker/Xray-core/app/proxyman/outbound"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/GFW-knocker/Xray-core/app/commander"
	_ "github.com/GFW-knocker/Xray-core/app/log/command"
	_ "github.com/GFW-knocker/Xray-core/app/proxyman/command"
	_ "github.com/GFW-knocker/Xray-core/app/stats/command"

	// Developer preview services
	_ "github.com/GFW-knocker/Xray-core/app/observatory/command"

	// Other optional features.
	_ "github.com/GFW-knocker/Xray-core/app/dns"
	_ "github.com/GFW-knocker/Xray-core/app/dns/fakedns"
	_ "github.com/GFW-knocker/Xray-core/app/log"
	_ "github.com/GFW-knocker/Xray-core/app/metrics"
	_ "github.com/GFW-knocker/Xray-core/app/policy"
	_ "github.com/GFW-knocker/Xray-core/app/reverse"
	_ "github.com/GFW-knocker/Xray-core/app/router"
	_ "github.com/GFW-knocker/Xray-core/app/stats"

	// Fix dependency cycle caused by core import in internet package
	_ "github.com/GFW-knocker/Xray-core/transport/internet/tagged/taggedimpl"

	// Developer preview features
	_ "github.com/GFW-knocker/Xray-core/app/observatory"

	// Inbound and outbound proxies.
	_ "github.com/GFW-knocker/Xray-core/proxy/blackhole"
	_ "github.com/GFW-knocker/Xray-core/proxy/dns"
	_ "github.com/GFW-knocker/Xray-core/proxy/dokodemo"
	_ "github.com/GFW-knocker/Xray-core/proxy/freedom"
	_ "github.com/GFW-knocker/Xray-core/proxy/http"
	_ "github.com/GFW-knocker/Xray-core/proxy/loopback"
	_ "github.com/GFW-knocker/Xray-core/proxy/shadowsocks"
	_ "github.com/GFW-knocker/Xray-core/proxy/socks"
	_ "github.com/GFW-knocker/Xray-core/proxy/trojan"
	_ "github.com/GFW-knocker/Xray-core/proxy/vless/inbound"
	_ "github.com/GFW-knocker/Xray-core/proxy/vless/outbound"
	_ "github.com/GFW-knocker/Xray-core/proxy/vmess/inbound"
	_ "github.com/GFW-knocker/Xray-core/proxy/vmess/outbound"
	_ "github.com/GFW-knocker/Xray-core/proxy/wireguard"

	// Transports
	_ "github.com/GFW-knocker/Xray-core/transport/internet/domainsocket"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/grpc"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/http"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/httpupgrade"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/kcp"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/quic"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/reality"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/tcp"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/tls"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/udp"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/websocket"

	// Transport headers
	_ "github.com/GFW-knocker/Xray-core/transport/internet/headers/http"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/headers/noop"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/headers/srtp"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/headers/tls"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/headers/utp"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/headers/wechat"
	_ "github.com/GFW-knocker/Xray-core/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/GFW-knocker/Xray-core/main/json"
	_ "github.com/GFW-knocker/Xray-core/main/toml"
	_ "github.com/GFW-knocker/Xray-core/main/yaml"

	// Load config from file or http(s)
	_ "github.com/GFW-knocker/Xray-core/main/confloader/external"

	// Commands
	_ "github.com/GFW-knocker/Xray-core/main/commands/all"
)
