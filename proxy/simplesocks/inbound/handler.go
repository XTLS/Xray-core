package simplesocks

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
)

func HandleInboundConnection(ctx context.Context, conn net.Conn, dispatcher routing.Dispatcher) error {
	sconn := NewInboundConn(conn)
	defer sconn.Close()

	if _, err := sconn.GetHeader(); err != nil {
		return err
	}

	link, err := dispatcher.Dispatch(ctx, sconn.header.Destination())
	if err != nil {
		return err
	}

	// Set up context
	v := core.MustFromContext(ctx)
	policyManager := v.GetFeature(policy.ManagerType()).(policy.Manager)
	sessionPolicy := policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	// Get server reader and writer
	serverReader := link.Reader
	serverWriter := link.Writer

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		if err := buf.Copy(buf.NewReader(sconn), serverWriter, buf.UpdateActivity(timer)); err != nil {
			return err
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		if err := buf.Copy(serverReader, buf.NewWriter(sconn), buf.UpdateActivity(timer)); err != nil {
			return err
		}
		return nil
	}

	if err := task.Run(ctx, task.OnSuccess(postRequest, task.Close(serverWriter)), getResponse); err != nil {
		common.Interrupt(serverReader)
		common.Interrupt(serverWriter)
		return err
	}

	return nil
}
