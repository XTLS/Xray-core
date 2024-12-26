package tcp

import (
	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
