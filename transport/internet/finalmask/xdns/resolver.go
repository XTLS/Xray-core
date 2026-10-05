package xdns

import (
	"errors"
	"net"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type Resolver interface {
	Addr() *net.UDPAddr
	Read(p []byte) (int, error)
	Send(p []byte)
	Close()
}

func NewResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	switch config.Type {
	case "tcp":
		return NewTCPResolver(config, dialer)
	case "udp":
		return NewUDPResolver(config, dialer)
	default:
		return nil, errors.New("unknown type")
	}
}
