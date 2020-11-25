package udp

import (
	"github.com/xtls/xray-core/v1/common"
	"github.com/xtls/xray-core/v1/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
