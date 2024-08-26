package udp

import (
	"github.com/xmplusdev/xray-core/common/buf"
	"github.com/xmplusdev/xray-core/common/net"
)

// Packet is a UDP packet together with its source and destination address.
type Packet struct {
	Payload *buf.Buffer
	Source  net.Destination
	Target  net.Destination
}
