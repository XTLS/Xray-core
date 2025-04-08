package udp

import (
	"github.com/hosemorinho412/xray-core/common"
	"github.com/hosemorinho412/xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
