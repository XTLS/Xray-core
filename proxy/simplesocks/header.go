package simplesocks

import "github.com/xtls/xray-core/common/net"

const (
	SIMPLE_SOCKS_CMD_CONNECT       = 1
	SIMPLE_SOCKS_CMD_UDP_ASSOCIATE = 3
)

const (
	SIMPLE_SOCKS_ATYPE_IPV4        = 1
	SIMPLE_SOCKS_ATYPE_DOMAIN_NAME = 3
	SIMPLE_SOCKS_ATYPE_IPV6        = 4
)

type Command byte
type Type byte

/*
 * +-----+------+----------+----------+
 * | CMD | ATYP | DST.ADDR | DST.PORT |
 * +-----+------+----------+----------+
 * |  1  |  1   | Variable |    2     |
 * +-----+------+----------+----------+
 * |            Payload               |
 * +-----+------+----------+----------+
 * |            Variable              |
 * +-----+------+----------+----------+
 */
type Header struct {
	Command Command
	Atype   Type
	Address net.Address
	Port    net.Port
}

func (h *Header) Destination() net.Destination {
	if h.Command == SIMPLE_SOCKS_CMD_UDP_ASSOCIATE {
		return net.UDPDestination(h.Address, h.Port)
	}
	return net.TCPDestination(h.Address, h.Port)
}
