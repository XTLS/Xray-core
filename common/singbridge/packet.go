package singbridge

import (
	"context"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

func CopyPacketConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, destination net.Destination, serverConn net.PacketConn) error {
	conn := &PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
		Conn:   inboundConn,
	}
	return ReturnError(bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(serverConn)))
}

type PacketConnWrapper struct {
	buf.Reader
	buf.Writer
	net.Conn
	Dest   net.Destination
	cached buf.MultiBuffer
}

func (w *PacketConnWrapper) ReadPacket(buffer *B.Buffer) (M.Socksaddr, error) {
	if w.cached != nil {
		mb, bb := buf.SplitFirst(w.cached)
		if bb == nil {
			w.cached = nil
		} else {
			buffer.Write(bb.Bytes())
			w.cached = mb
			var destination net.Destination = w.Dest
			if bb.UDP != nil {
				destination = *bb.UDP
			}
			bb.Release()
			return ToSocksaddr(destination), nil
		}
	}
	mb, err := w.ReadMultiBuffer()
	if err != nil {
		return M.Socksaddr{}, err
	}
	nb, bb := buf.SplitFirst(mb)
	if bb == nil {
		return M.Socksaddr{}, nil
	} else {
		buffer.Write(bb.Bytes())
		w.cached = nb
		var destination net.Destination = w.Dest
		if bb.UDP != nil {
			destination = *bb.UDP
		}
		bb.Release()
		return ToSocksaddr(destination), nil
	}
}

func (w *PacketConnWrapper) WritePacket(buffer *B.Buffer, destination M.Socksaddr) error {
	vBuf := buf.New()
	vBuf.Write(buffer.Bytes())
	endpoint := ToDestination(destination, net.Network_UDP)
	vBuf.UDP = &endpoint
	return w.Writer.WriteMultiBuffer(buf.MultiBuffer{vBuf})
}

func (w *PacketConnWrapper) Close() error {
	buf.ReleaseMulti(w.cached)
	return nil
}
