// Package vless contains the implementation of VLess protocol and transportation.
//
// VLess contains both inbound and outbound connections. VLess inbound is usually used on servers
// together with 'freedom' to talk to final destination, while VLess outbound is usually used on
// clients with 'socks' for proxying.
package vless

//go:generate go run github.com/4nd3r5on/Xray-core/common/errors/errorgen

const (
	XRV = "xtls-rprx-vision"
)
