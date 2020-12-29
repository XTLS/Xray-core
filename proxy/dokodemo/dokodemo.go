package dokodemo

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DokodemoDoor)
		err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
			return d.Init(config.(*Config), pm, session.SockoptFromContext(ctx))
		})
		return d, err
	}))
}

type DokodemoDoor struct {
	policyManager policy.Manager
	config        *Config
	address       net.Address
	port          net.Port
	sockopt       *session.Sockopt
}

// Init initializes the DokodemoDoor instance with necessary parameters.
func (d *DokodemoDoor) Init(config *Config, pm policy.Manager, sockopt *session.Sockopt) error {
	if (config.NetworkList == nil || len(config.NetworkList.Network) == 0) && len(config.Networks) == 0 {
		return newError("no network specified")
	}
	d.config = config
	d.address = config.GetPredefinedAddress()
	d.port = net.Port(config.Port)
	d.policyManager = pm
	d.sockopt = sockopt

	return nil
}

// Network implements proxy.Inbound.
func (d *DokodemoDoor) Network() []net.Network {
	if len(d.config.Networks) > 0 {
		return d.config.Networks
	}

	return d.config.NetworkList.Network
}

func (d *DokodemoDoor) policy() policy.Session {
	config := d.config
	p := d.policyManager.ForLevel(config.UserLevel)
	if config.Timeout > 0 && config.UserLevel == 0 {
		p.Timeouts.ConnectionIdle = time.Duration(config.Timeout) * time.Second
	}
	return p
}

type hasHandshakeAddress interface {
	HandshakeAddress() net.Address
}

// Process implements proxy.Inbound.
func (d *DokodemoDoor) Process(ctx context.Context, network net.Network, conn internet.Connection, dispatcher routing.Dispatcher) error {
	newError("processing connection from: ", conn.RemoteAddr()).AtDebug().WriteToLog(session.ExportIDToError(ctx))
	dest := net.Destination{
		Network: network,
		Address: d.address,
		Port:    d.port,
	}

	destinationOverridden := false
	if d.config.FollowRedirect {
		if outbound := session.OutboundFromContext(ctx); outbound != nil && outbound.Target.IsValid() {
			dest = outbound.Target
			destinationOverridden = true
		} else if handshake, ok := conn.(hasHandshakeAddress); ok {
			addr := handshake.HandshakeAddress()
			if addr != nil {
				dest.Address = addr
				destinationOverridden = true
			}
		}
	}
	if !dest.IsValid() || dest.Address == nil {
		return newError("unable to get destination")
	}

	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.User = &protocol.MemoryUser{
			Level: d.config.UserLevel,
		}
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})
	newError("received request for ", conn.RemoteAddr()).WriteToLog(session.ExportIDToError(ctx))

	plcy := d.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, plcy.Timeouts.ConnectionIdle)

	if inbound != nil {
		inbound.Timer = timer
	}

	ctx = policy.ContextWithBufferPolicy(ctx, plcy.Buffer)
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return newError("failed to dispatch request").Base(err)
	}

	requestCount := int32(1)
	requestDone := func() error {
		defer func() {
			if atomic.AddInt32(&requestCount, -1) == 0 {
				timer.SetTimeout(plcy.Timeouts.DownlinkOnly)
			}
		}()

		var reader buf.Reader
		if dest.Network == net.Network_UDP {
			reader = buf.NewPacketReader(conn)
		} else {
			reader = buf.NewReader(conn)
		}
		if err := buf.Copy(reader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport request").Base(err)
		}

		return nil
	}

	tproxyRequest := func() error {
		return nil
	}

	var writer buf.Writer
	if network == net.Network_TCP {
		writer = buf.NewWriter(conn)
	} else {
		// if we are in TPROXY mode, use linux's udp forging functionality
		if !destinationOverridden {
			writer = &buf.SequentialWriter{Writer: conn}
		} else {
			sockopt := &internet.SocketConfig{
				Tproxy: internet.SocketConfig_TProxy,
			}
			if dest.Address.Family().IsIP() {
				sockopt.BindAddress = dest.Address.IP()
				sockopt.BindPort = uint32(dest.Port)
			}
			if d.sockopt != nil {
				sockopt.Mark = d.sockopt.Mark
			}
			to := net.DestinationFromAddr(conn.RemoteAddr())
			tConn, err := internet.DialSystem(ctx, to, sockopt)
			if err != nil {
				return err
			}
			writer = NewPacketWriter(tConn, &dest, ctx, &to, sockopt)
			defer writer.(*PacketWriter).Close()
			/*
				defer tConn.Close()
				writer = &buf.SequentialWriter{Writer: tConn}
				tReader := buf.NewPacketReader(tConn)
				requestCount++
				tproxyRequest = func() error {
					defer func() {
						if atomic.AddInt32(&requestCount, -1) == 0 {
							timer.SetTimeout(plcy.Timeouts.DownlinkOnly)
						}
					}()
					if err := buf.Copy(tReader, link.Writer, buf.UpdateActivity(timer)); err != nil {
						return newError("failed to transport request (TPROXY conn)").Base(err)
					}
					return nil
				}
			*/
		}
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)

		if err := buf.Copy(link.Reader, writer, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport response").Base(err)
		}
		return nil
	}

	if err := task.Run(ctx, task.OnSuccess(func() error {
		return task.Run(ctx, requestDone, tproxyRequest)
	}, task.Close(link.Writer)), responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}

	return nil
}

func NewPacketWriter(conn net.Conn, d *net.Destination, ctx context.Context, to *net.Destination, sockopt *internet.SocketConfig) buf.Writer {
	writer := &PacketWriter{
		conn:    conn,
		conns:   make(map[net.Destination]net.Conn),
		ctx:     ctx,
		to:      to,
		sockopt: sockopt,
	}
	writer.conns[*d] = conn
	return writer
}

type PacketWriter struct {
	conn    net.Conn
	conns   map[net.Destination]net.Conn
	ctx     context.Context
	to      *net.Destination
	sockopt *internet.SocketConfig
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		var err error
		if b.UDP != nil && b.UDP.Address.Family().IsIP() {
			conn := w.conns[*b.UDP]
			if conn == nil {
				w.sockopt.BindAddress = b.UDP.Address.IP()
				w.sockopt.BindPort = uint32(b.UDP.Port)
				conn, _ = internet.DialSystem(w.ctx, *w.to, w.sockopt)
				if conn == nil {
					b.Release()
					continue
				}
				w.conns[*b.UDP] = conn
			}
			_, err = conn.Write(b.Bytes())
		} else {
			_, err = w.conn.Write(b.Bytes())
		}
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

func (w *PacketWriter) Close() error {
	for _, conn := range w.conns {
		if conn != nil {
			conn.Close()
		}
	}
	return nil
}
