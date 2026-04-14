// Package xtess contains the implementation of XTess protocol and transportation.
//
// XTess contains both inbound and outbound connections. XTess inbound is usually used on servers
// together with 'freedom' to talk to final destination, while XTess outbound is usually used on
// clients with 'socks' for proxying.
package xtess

const (
	None = "none"
	XRV  = "xtls-rprx-vision"
)

