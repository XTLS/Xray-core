package taggedimpl

import (
	"context"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/net/cnc"
	"github.com/GFW-knocker/Xray-core/common/session"
	"github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/features/routing"
	"github.com/GFW-knocker/Xray-core/transport/internet/tagged"
)

func DialTaggedOutbound(ctx context.Context, dispatcher routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
	if core.FromContext(ctx) == nil {
		return nil, errors.New("Instance context variable is not in context, dial denied. ")
	}
	content := new(session.Content)
	content.SkipDNSResolve = true

	ctx = session.ContextWithContent(ctx, content)
	ctx = session.SetForcedOutboundTagToContext(ctx, tag)

	r, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return nil, err
	}
	var readerOpt cnc.ConnectionOption
	if dest.Network == net.Network_TCP {
		readerOpt = cnc.ConnectionOutputMulti(r.Reader)
	} else {
		readerOpt = cnc.ConnectionOutputMultiUDP(r.Reader)
	}
	return cnc.NewConnection(cnc.ConnectionInputMulti(r.Writer), readerOpt), nil
}

func init() {
	tagged.Dialer = DialTaggedOutbound
}
