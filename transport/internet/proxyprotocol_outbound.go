package internet

import (
	"context"
	"io"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func WriteProxyProtocolHeader(writer io.Writer, version uint32, srcAddr, dstAddr net.Addr) error {
	header := proxyproto.HeaderProxyFromAddrs(byte(version), srcAddr, dstAddr)
	if _, err := header.WriteTo(writer); err != nil {
		return errors.New("failed to set PROXY protocol v", version).Base(err)
	}
	return nil
}

func WriteOutboundProxyProtocol(ctx context.Context, conn net.Conn, sockopt *SocketConfig) error {
	if sockopt == nil || sockopt.SendProxyProtocol == 0 {
		return nil
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !inbound.Source.IsValid() || !inbound.Local.IsValid() {
		return nil
	}

	return WriteProxyProtocolHeader(conn, sockopt.SendProxyProtocol, inbound.Source.RawNetAddr(), inbound.Local.RawNetAddr())
}
