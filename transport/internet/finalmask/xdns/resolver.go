package xdns

import (
	"errors"
	"net"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type Resolver interface {
	Addr() *net.UDPAddr
	Read(p []byte) (int, error)
	Send(p []byte)
	Close()
}

func NewResolver(proto *serial.TypedMessage, dialer *finalmask.Dialer) (Resolver, error) {
	config, err := proto.GetInstance()
	if err != nil {
		return nil, err
	}
	switch v := config.(type) {
	case *TCPResolverProto:
		return NewTCPResolver(v, dialer)
	case *UDPResolverProto:
		return NewUDPResolver(v, dialer)
	default:
		return nil, errors.New("unknown proto")
	}
}
