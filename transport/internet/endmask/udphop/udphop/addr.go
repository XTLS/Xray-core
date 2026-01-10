package udphop

import (
	"fmt"
	"net"

	"github.com/xtls/xray-core/transport/internet/endmask/udphop/utils"
)

type InvalidPortError struct {
	PortStr string
}

func (e InvalidPortError) Error() string {
	return fmt.Sprintf("%s is not a valid port number or range", e.PortStr)
}

// UDPHopAddr contains a list of ports (IP address is not stored, will be taken from the upper layer).
type UDPHopAddr struct {
	Ports   []uint16
	PortStr string
}

func (a *UDPHopAddr) Network() string {
	return "udphop"
}

func (a *UDPHopAddr) String() string {
	return net.JoinHostPort("", a.PortStr)
}

// addrs returns a list of ports (without IP, IP will be taken from WriteTo parameter).
func (a *UDPHopAddr) ports() []uint16 {
	return a.Ports
}

func ResolveUDPHopAddr(addr string) (*UDPHopAddr, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// IP address is ignored, only port information is kept
	result := &UDPHopAddr{
		PortStr: portStr,
	}

	pu := utils.ParsePortUnion(portStr)
	if pu == nil {
		return nil, InvalidPortError{portStr}
	}
	result.Ports = pu.Ports()

	return result, nil
}
