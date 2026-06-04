package ssh

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xssh "golang.org/x/crypto/ssh"
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Server == nil {
		return nil, errors.New("no SSH server found")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get SSH server spec").Base(err)
	}

	v := core.MustFromContext(ctx)
	return &Client{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("missing outbound context")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "ssh"
	ob.CanSpliceCopy = 2
	target := ob.Target
	if target.Network == net.Network_UDP {
		return errors.New("UDP is not supported by SSH outbound")
	}

	server := c.server
	user := server.User
	if user == nil || user.Account == nil {
		return errors.New("SSH account is missing")
	}
	account, ok := user.Account.(*Account)
	if !ok {
		return errors.New("unexpected SSH account type")
	}

	p := c.policyManager.ForLevel(0)
	if user != nil {
		p = c.policyManager.ForLevel(user.Level)
	}

	var rawConn stat.Connection
	var sshClient *xssh.Client
	var targetConn net.Conn
	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		sshConfig, err := account.BuildClientConfig(nil)
		if err != nil {
			return err
		}
		conn, err := dialer.Dial(ctx, server.Destination)
		if err != nil {
			return err
		}
		rawConn = conn
		if err := rawConn.SetDeadline(time.Now().Add(p.Timeouts.Handshake)); err != nil {
			errors.LogInfoInner(ctx, err, "failed to set SSH handshake deadline")
		}
		clientConn, chans, reqs, err := xssh.NewClientConn(rawConn, server.Destination.NetAddr(), sshConfig)
		if err != nil {
			common.Close(rawConn)
			rawConn = nil
			return err
		}
		sshClient = xssh.NewClient(clientConn, chans, reqs)
		targetConn, err = sshClient.Dial("tcp", target.NetAddr())
		if err != nil {
			common.Close(sshClient)
			common.Close(rawConn)
			sshClient = nil
			rawConn = nil
			return err
		}
		if err := rawConn.SetDeadline(time.Time{}); err != nil {
			errors.LogInfoInner(ctx, err, "failed to clear SSH deadline")
		}
		return nil
	}); err != nil {
		return errors.New("failed to establish SSH outbound connection").Base(err)
	}
	defer common.Close(targetConn)
	defer common.Close(sshClient)
	defer common.Close(rawConn)

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, p.Timeouts.ConnectionIdle)

	requestFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(targetConn), buf.UpdateActivity(timer))
	}
	responseFunc := func() error {
		ob.CanSpliceCopy = 1
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(targetConn), link.Writer, buf.UpdateActivity(timer))
	}

	if newCtx != nil {
		ctx = newCtx
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
