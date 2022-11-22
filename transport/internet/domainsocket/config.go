package domainsocket

import (
	"github.com/jobberrt/xray-core/common"
	"github.com/jobberrt/xray-core/common/net"
	"github.com/jobberrt/xray-core/transport/internet"
)

const (
	protocolName  = "domainsocket"
	sizeofSunPath = 108
)

func (c *Config) GetUnixAddr() (*net.UnixAddr, error) {
	path := c.Path
	if path == "" {
		return nil, newError("empty domain socket path")
	}
	if c.Abstract && path[0] != '@' {
		path = "@" + path
	}
	if c.Abstract && c.Padding {
		raw := []byte(path)
		addr := make([]byte, sizeofSunPath)
		copy(addr, raw)
		path = string(addr)
	}
	return &net.UnixAddr{
		Name: path,
		Net:  "unix",
	}, nil
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
