package hysteria2

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/xtls/xray-core/common/session"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// recordingDialer captures context and destination used by dialerConnFactory.
type recordingDialer struct {
	ctx  context.Context
	dest xnet.Destination
}

func (r *recordingDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	r.ctx = ctx
	r.dest = dest
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (r *recordingDialer) DestIpAddress() net.IP { return nil }

func (r *recordingDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

// Ensure dialerConnFactory injects Outbounds into context when absent.
func TestDialerConnFactoryContextHasOutbound(t *testing.T) {
	dest := xnet.UDPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(12345))
	rd := &recordingDialer{}
	f := &dialerConnFactory{
		ctx:    context.Background(),
		dialer: rd,
		dest:   dest,
	}

	pc, err := f.New(nil)
	require.NoError(t, err)
	require.NotNil(t, pc)
	_ = pc.Close()

	outs := session.OutboundsFromContext(rd.ctx)
	require.NotNil(t, outs)
	require.Len(t, outs, 1)
	require.Equal(t, dest, outs[0].Target)
}
