package udp

import (
	"github.com/xtls/xray-core/v1/common/buf"
	"github.com/xtls/xray-core/v1/common/net"
)

// Packet is a UDP packet together with its source and destination address.
type Packet struct {
	Payload *buf.Buffer
	Source  net.Destination
	Target  net.Destination
}
