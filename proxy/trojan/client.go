package trojan

import (
	"context"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/xtls"
)

// Client is a inbound handler for trojan protocol
type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
}

// NewClient create a new trojan client.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	serverList := protocol.NewServerList()
	for _, rec := range config.Server {
		s, err := protocol.NewServerSpecFromPB(rec)
		if err != nil {
			return nil, newError("failed to parse server spec").Base(err)
		}
		serverList.AddServer(s)
	}
	if serverList.Size() == 0 {
		return nil, newError("0 server")
	}

	v := core.MustFromContext(ctx)
	client := &Client{
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}
	return client, nil
}

// Process implements OutboundHandler.Process().
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	destination := outbound.Target
	network := destination.Network

	var server *protocol.ServerSpec
	var conn stat.Connection

	err := retry.ExponentialBackoff(5, 100).On(func() error {
		server = c.serverPicker.PickServer()
		rawConn, err := dialer.Dial(ctx, server.Destination())
		if err != nil {
			return err
		}

		conn = rawConn
		return nil
	})
	if err != nil {
		return newError("failed to find an available destination").AtWarning().Base(err)
	}
	newError("tunneling request to ", destination, " via ", server.Destination().NetAddr()).WriteToLog(session.ExportIDToError(ctx))

	defer conn.Close()

	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}

	user := server.PickUser()
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return newError("user account is not valid")
	}

	connWriter := &ConnWriter{
		Flow: account.Flow,
	}

	var rawConn syscall.RawConn
	var sctx context.Context

	allowUDP443 := false
	switch connWriter.Flow {
	case XRO + "-udp443", XRD + "-udp443", XRS + "-udp443":
		allowUDP443 = true
		connWriter.Flow = connWriter.Flow[:16]
		fallthrough
	case XRO, XRD, XRS:
		if destination.Address.Family().IsDomain() && destination.Address.Domain() == muxCoolAddress {
			return newError(connWriter.Flow + " doesn't support Mux").AtWarning()
		}
		if destination.Network == net.Network_UDP {
			if !allowUDP443 && destination.Port == 443 {
				return newError(connWriter.Flow + " stopped UDP/443").AtInfo()
			}
			connWriter.Flow = ""
		} else { // enable XTLS only if making TCP request
			if xtlsConn, ok := iConn.(*xtls.Conn); ok {
				xtlsConn.RPRX = true
				xtlsConn.SHOW = xtls_show
				xtlsConn.MARK = "XTLS"
				if connWriter.Flow == XRS {
					sctx = ctx
					connWriter.Flow = XRD
				}
				if connWriter.Flow == XRD {
					xtlsConn.DirectMode = true
					if sc, ok := xtlsConn.Connection.(syscall.Conn); ok {
						rawConn, _ = sc.SyscallConn()
					}
				}
			} else {
				return newError(`failed to use ` + connWriter.Flow + `, maybe "security" is not "xtls"`).AtWarning()
			}
		}
	default:
		if _, ok := iConn.(*xtls.Conn); ok {
			panic(`To avoid misunderstanding, you must fill in Trojan "flow" when using XTLS.`)
		}
	}

	sessionPolicy := c.policyManager.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))

		connWriter.Writer = bufferWriter
		connWriter.Target = destination
		connWriter.Account = account

		var bodyWriter buf.Writer
		if destination.Network == net.Network_UDP {
			bodyWriter = &PacketWriter{Writer: connWriter, Target: destination}
		} else {
			bodyWriter = connWriter
		}

		// write some request payload to buffer
		if err = buf.CopyOnceTimeout(link.Reader, bodyWriter, time.Millisecond*100); err != nil && err != buf.ErrNotTimeoutReader && err != buf.ErrReadTimeout {
			return newError("failed to write A request payload").Base(err).AtWarning()
		}

		// Flush; bufferWriter.WriteMultiBufer now is bufferWriter.writer.WriteMultiBuffer
		if err = bufferWriter.SetBuffered(false); err != nil {
			return newError("failed to flush payload").Base(err).AtWarning()
		}

		// Send header if not sent yet
		if _, err = connWriter.Write([]byte{}); err != nil {
			return err.(*errors.Error).AtWarning()
		}

		if err = buf.Copy(link.Reader, bodyWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transfer request payload").Base(err).AtInfo()
		}

		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		var reader buf.Reader
		if network == net.Network_UDP {
			reader = &PacketReader{
				Reader: conn,
			}
		} else {
			reader = buf.NewReader(conn)
		}
		if rawConn != nil {
			var counter stats.Counter
			if statConn != nil {
				counter = statConn.ReadCounter
			}
			return ReadV(reader, link.Writer, timer, iConn.(*xtls.Conn), rawConn, counter, sctx)
		}
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}

	responseDoneAndCloseWriter := task.OnSuccess(getResponse, task.Close(link.Writer))
	if err := task.Run(ctx, postRequest, responseDoneAndCloseWriter); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))

	const defaultFlagValue = "NOT_DEFINED_AT_ALL"

	xtlsShow := platform.NewEnvFlag("xray.trojan.xtls.show").GetValue(func() string { return defaultFlagValue })
	if xtlsShow == "true" {
		xtls_show = true
	}
}
