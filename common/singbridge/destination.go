package singbridge

import (
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

func ToNetwork(network string) net.Network {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return net.Network_TCP
	case N.NetworkUDP:
		return net.Network_UDP
	default:
		return net.Network_Unknown
	}
}

func ToDestination(socksaddr M.Socksaddr, network net.Network) (net.Destination, error) {
	// IsFqdn() implicitly checks if the domain name is valid
	if socksaddr.IsFqdn() {
		return net.Destination{
			Network: network,
			Address: net.DomainAddress(socksaddr.Fqdn),
			Port:    net.Port(socksaddr.Port),
		}, nil
	}

	// IsIP() implicitly checks if the IP address is valid
	if socksaddr.IsIP() {
		return net.Destination{
			Network: network,
			Address: net.IPAddress(socksaddr.Addr.AsSlice()),
			Port:    net.Port(socksaddr.Port),
		}, nil
	}

	return net.Destination{}, errors.New("invalid socks address: ", socksaddr)
}

func ToSocksaddr(destination net.Destination) M.Socksaddr {
	var addr M.Socksaddr
	switch destination.Address.Family() {
	case net.AddressFamilyDomain:
		addr.Fqdn = destination.Address.Domain()
	default:
		addr.Addr = M.AddrFromIP(destination.Address.IP())
	}
	addr.Port = uint16(destination.Port)
	return addr
}
