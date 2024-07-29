package tcp

import (
	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/transport/internet"
)

const protocolName = "tcp"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
