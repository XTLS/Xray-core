package xdns

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type UDPResolver struct { *socketResolver }

func NewUDPResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	dest, addr, err := resolverTarget(config.Addr, "", net.Network_UDP)
	if err != nil { return nil, err }
	if dialer == nil || (dialer.DialUDPContext == nil && dialer.DialUDP == nil) { return nil, errors.New("missing UDP dialer") }
	r, err := newSocketResolver(addr, false, func(ctx context.Context) (net.Conn, error) {
		var conn net.Conn
		var err error
		if dialer.DialUDPContext != nil { conn, err = dialer.DialUDPContext(ctx, dest) } else { conn, err = dialer.DialUDP(dest) }
		if err != nil { return nil, err }
		wrapper, ok := conn.(*net.PacketConnWrapper)
		if !ok || wrapper.PacketConn == nil || wrapper.Dest == nil {
			if conn != nil { conn.Close() }
			return nil, errors.New("UDP dialer must return a PacketConnWrapper with a destination")
		}
		return conn, nil
	})
	if err != nil { return nil, err }
	return &UDPResolver{r}, nil
}
