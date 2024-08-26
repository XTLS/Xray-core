package udp

import (
	"github.com/xmplusdev/xray-core/common"
	"github.com/xmplusdev/xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
