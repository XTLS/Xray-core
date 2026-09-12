package xdns

import (
	"errors"
	"net"

	"github.com/xtls/xray-core/common/serial"
)

type Resolver interface {
	Addr() *net.UDPAddr
	Read(p []byte) (int, error)
	Send(p []byte)
	Close()
}

func NewResolver(proto *serial.TypedMessage) (Resolver, error) {
	config, err := proto.GetInstance()
	if err != nil {
		return nil, err
	}
	switch v := config.(type) {
	case *TCPResolverProto:
		return NewTCPResolver(v)
	case *UDPResolverProto:
		return NewUDPResolver(v)
	default:
		return nil, errors.New("unknown proto")
	}
}
