package tcp

import (
	"github.com/NamiraNet/xray-core/common"
	"github.com/NamiraNet/xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
