package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type legacyPacketEcho struct{}

func (legacyPacketEcho) Process(_ context.Context, link *transport.Link, _ internet.Dialer) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	return link.Writer.WriteMultiBuffer(mb)
}

func TestPacketLegacyOutboundUsesPrivateLeg(t *testing.T) {
	dest := net.UDPDestination(net.LocalHostIP, 12345)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{OriginalTarget: dest, Target: dest}})
	h := &Handler{proxy: legacyPacketEcho{}}
	leg, err := h.PreparePacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer leg.Abort()
	if n, err := leg.Writer.WritePacket([]byte{1, 2, 3}, dest); err != nil || n != 3 {
		t.Fatalf("legacy write n=%d err=%v", n, err)
	}
	buf := make([]byte, 8)
	n, from, err := leg.Reader.ReadPacket(buf)
	if err != nil || n != 3 || from != dest || buf[0] != 1 || buf[2] != 3 {
		t.Fatalf("legacy reply n=%d from=%v err=%v", n, from, err)
	}
}
