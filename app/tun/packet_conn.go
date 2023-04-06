package tun

import (
	sing_common "github.com/sagernet/sing/common"
	sing_buf "github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singbridge"
)

type PacketConn struct {
	N.PacketConn
}

func (p *PacketConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	packet := buf.New()
	packet.Extend(buf.Size)
	sPacket := sing_buf.With(packet.Bytes())
	destination, err := p.ReadPacket(sPacket)
	if err != nil {
		packet.Release()
		return nil, err
	}
	packet.Clear()
	packet.Resize(int32(sPacket.Start()), int32(sPacket.Start()+sPacket.Len()))
	destinationX := singbridge.ToDestination(destination, net.Network_UDP)
	packet.UDP = &destinationX
	return buf.MultiBuffer{packet}, nil
}

func (p *PacketConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, buffer := range mb {
		destination := sing_common.PtrValueOrDefault(buffer.UDP)
		err := p.PacketConn.WritePacket(sing_buf.As(buffer.Bytes()), singbridge.ToSocksaddr(destination))
		if err != nil {
			return err
		}
	}
	return nil
}
