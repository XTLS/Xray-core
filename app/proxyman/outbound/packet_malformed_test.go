package outbound

import (
	"context"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet"
	"io"
	"testing"
)

type malformedPacketProxy struct {
	endpoint exchange.PacketEndpoint
	err      error
}

func (p malformedPacketProxy) Process(context.Context, *transport.Link, internet.Dialer) error {
	return nil
}
func (p malformedPacketProxy) PreparePacket(context.Context, internet.Dialer) (exchange.PacketEndpoint, error) {
	return p.endpoint, p.err
}

func TestPacketPrepareErrorAbortsReturnedResource(t *testing.T) {
	aborted := false
	ep := exchange.PacketEndpoint{Abort: func() { aborted = true }}
	h := &Handler{proxy: malformedPacketProxy{endpoint: ep, err: io.ErrClosedPipe}}
	dest := net.UDPDestination(net.LocalHostIP, 1234)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{OriginalTarget: dest, Target: dest}})
	if _, err := h.PreparePacket(ctx); err != io.ErrClosedPipe || !aborted {
		t.Fatalf("err=%v aborted=%v", err, aborted)
	}
}
func TestPacketRejectsMalformedEndpointBeforeAddressWrapping(t *testing.T) {
	for _, kind := range []string{"reader", "writer", "abort"} {
		t.Run(kind, func(t *testing.T) {
			p := &addressPacket{dest: net.UDPDestination(net.LocalHostIP, 1)}
			aborted := false
			ep := exchange.PacketEndpoint{Reader: p, Writer: p, Abort: func() { aborted = true }}
			switch kind {
			case "reader":
				ep.Reader = nil
			case "writer":
				ep.Writer = nil
			case "abort":
				ep.Abort = nil
			}
			h := &Handler{proxy: malformedPacketProxy{endpoint: ep}}
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{OriginalTarget: net.UDPDestination(net.DomainAddress("first.test"), 1), Target: net.UDPDestination(net.LocalHostIP, 1)}})
			if _, err := h.PreparePacket(ctx); err == nil {
				t.Fatal("malformed endpoint admitted")
			}
			if kind != "abort" && !aborted {
				t.Fatal("malformed result not aborted")
			}
		})
	}
}
