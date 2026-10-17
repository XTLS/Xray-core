// Package vless contains the implementation of VLess protocol and transportation.
//
// VLess contains both inbound and outbound connections. VLess inbound is usually used on servers
// together with 'freedom' to talk to final destination, while VLess outbound is usually used on
// clients with 'socks' for proxying.
package vless

import (
	"bytes"
	"net"
	"reflect"

	"github.com/xtls/xray-core/common/utils"
)

const (
	None = "none"
	XRV  = "xtls-rprx-vision"
)

// Old TLS lib holds bytes.Buffer, but new TLS lib holds *bytes.Buffer
// Since Xray has 3 TLS libraries (std, utls, REALITY server)
// we detect the type of rawInput and return the appropriate pointer
func AccessTLSBuffers(conn net.Conn) (*bytes.Reader, **bytes.Buffer) {
	input := utils.AccessField[bytes.Reader](conn, "input")
	field := reflect.ValueOf(conn).Elem().FieldByName("rawInput")
	if field.Kind() == reflect.Pointer {
		return input, utils.AccessField[*bytes.Buffer](conn, "rawInput")
	}
	raw := utils.AccessField[bytes.Buffer](conn, "rawInput")
	return input, &raw
}
