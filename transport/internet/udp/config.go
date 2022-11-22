package udp

import (
	"github.com/jobberrt/xray-core/common"
	"github.com/jobberrt/xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
