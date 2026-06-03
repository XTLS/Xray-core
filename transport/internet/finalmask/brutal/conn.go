//go:build !linux

package brutal

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/errors"
)

func NewConn(c *Config, raw net.Conn) (net.Conn, error) {
	errors.LogError(context.Background(), "unsupported system")
	return raw, nil
}
