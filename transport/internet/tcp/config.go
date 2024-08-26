package tcp

import (
	"github.com/xmplusdev/xray-core/common"
	"github.com/xmplusdev/xray-core/transport/internet"
)

const protocolName = "tcp"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
