package simplesocks

import (
	"context"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/simplesocks"
	"github.com/xtls/xray-core/transport"
)

func HandleOutboundConnection(ctx context.Context, conn net.Conn, link *transport.Link, header *protocol.RequestHeader) error {
	sconn := NewOutboundConn(
		conn,
		simplesocks.SIMPLE_SOCKS_CMD_CONNECT,
		simplesocks.SIMPLE_SOCKS_ATYPE_IPV4,
		header.Address,
		header.Port)

	v := core.MustFromContext(ctx)
	policyManager := v.GetFeature(policy.ManagerType()).(policy.Manager)
	sessionPolicy := policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader
	clientWriter := link.Writer

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		// from clientReader.ReadMultiBuffer to serverWriter.WriteMultiBuffer
		if err := buf.Copy(clientReader, buf.NewWriter(sconn), buf.UpdateActivity(timer)); err != nil {
			return err
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		err := buf.Copy(buf.NewReader(sconn), clientWriter, buf.UpdateActivity(timer))
		if err != nil {
			return err
		}
		return nil
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return err
	}
	return nil
}
