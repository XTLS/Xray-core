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
	var err error
	config, err = normalizeResolver(config)
	if err != nil {
		return nil, err
	}
	if dialer == nil {
		return nil, errors.New("resolver dialer is unavailable")
	}
	switch config.Type {
	case "tcp":
		if dialer.DialTCP == nil {
			return nil, errors.New("resolver TCP dialer is unavailable")
		}
		return NewTCPResolver(config, dialer)
	case "udp":
		if dialer.DialUDP == nil {
			return nil, errors.New("resolver UDP dialer is unavailable")
		}
		return NewUDPResolver(config, dialer)
	case "dot":
		return NewDOTResolver(config, dialer)
	case "doh":
		return NewDOHResolver(config, dialer)
	default:
		return nil, errors.New("unknown type")
	}
}
