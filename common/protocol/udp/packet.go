package udp

import (
	"github.com/4nd3r5on/Xray-core/common/buf"
	"github.com/4nd3r5on/Xray-core/common/net"
)

// Packet is a UDP packet together with its source and destination address.
type Packet struct {
	Payload *buf.Buffer
	Source  net.Destination
	Target  net.Destination
}
