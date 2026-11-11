package multiplex_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func newLinkPair() (*transport.Link, *transport.Link) {
	opt := pipe.WithoutSizeLimit()
	uplinkReader, uplinkWriter := pipe.New(opt)
	downlinkReader, downlinkWriter := pipe.New(opt)

	uplink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	downlink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	return uplink, downlink
}

func TestRegressionOutboundLeak(t *testing.T) {
	originalOutbounds := []*session.Outbound{{}}
	serverCtx := session.ContextWithOutbounds(context.Background(), originalOutbounds)

	websiteUplink, websiteDownlink := newLinkPair()

	dispatch := func(ctx context.Context, dest net.Destination, link *transport.Link) error {
		// Emulate DefaultDispatcher's context mutation while forwarding real data.
		ob := session.OutboundsFromContext(ctx)[0]
		ob.Target = dest
		return task.Run(ctx,
			func() error { return buf.Copy(link.Reader, websiteDownlink.Writer) },
			func() error { return buf.Copy(websiteDownlink.Reader, link.Writer) })
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	multiplex.NewServerWorker(serverCtx, dispatch, muxServerUplink)

	client := multiplex.NewClientWorker(*muxServerDownlink, multiplex.ClientStrategy{})

	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})

	muxClientUplink, muxClientDownlink := newLinkPair()

	ok := client.Dispatch(clientCtx, muxClientUplink, false)
	if !ok {
		t.Error("failed to dispatch")
	}

	{
		b := buf.FromBytes([]byte("hello"))
		common.Must(muxClientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err := websiteUplink.Reader.ReadMultiBuffer()
	common.Must(err)
	res := resMb.String()
	if res != "hello" {
		t.Error("upload: ", res)
	}

	{
		b := buf.FromBytes([]byte("world"))
		common.Must(websiteUplink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err = muxClientDownlink.Reader.ReadMultiBuffer()
	common.Must(err)
	res = resMb.String()
	if res != "world" {
		t.Error("download: ", res)
	}

	outbounds := session.OutboundsFromContext(serverCtx)
	if outbounds[0] != originalOutbounds[0] {
		t.Error("outbound got reassigned: ", outbounds[0])
	}

	if outbounds[0].Target.Address != nil {
		t.Error("outbound target got leaked: ", outbounds[0].Target.String())
	}
}
