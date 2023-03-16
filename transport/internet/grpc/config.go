package grpc

import (
	"net/url"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

const protocolName = "grpc"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

func (c *Config) getServiceName() string {
	// Normal old school config
	if !strings.HasPrefix(c.ServiceName, "/") {
		return url.PathEscape(c.ServiceName)
	}
	// Otherwise new custom paths
	tunListen := strings.Split(c.ServiceName, ",")[0]
	return tunListen[1:strings.LastIndex(tunListen, "/")] // trim from first to last '/'
}

func (c *Config) getTunStreamName() string {
	// Normal old school config
	if !strings.HasPrefix(c.ServiceName, "/") {
		return "Tun"
	}
	// Otherwise new custom paths
	tunListen := strings.Split(c.ServiceName, ",")[0]
	return tunListen[strings.LastIndex(tunListen, "/")+1:] // from the last '/' to the end
}

func (c *Config) getMultiTunStreamName() string {
	// Normal old school config
	if !strings.HasPrefix(c.ServiceName, "/") {
		return "TunMulti"
	}
	// Otherwise new custom paths
	splitServiceName := strings.Split(c.ServiceName, ",")
	var fullPath string
	if len(splitServiceName) == 1 { // client side. Service name is the full path to multi tun
		fullPath = splitServiceName[0]
	} else { // server side. The second part is the path to multi tun
		fullPath = splitServiceName[1]
	}
	return fullPath[strings.LastIndex(fullPath, "/")+1:] // from the last '/' to the end
}
