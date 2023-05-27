package shadowsocks_2022

import (
	"context"
	"runtime"
	"time"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type Outbound struct {
	ctx       context.Context
	server    net.Destination
	method    shadowsocks.Method
	uotClient *uot.Client
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	o := &Outbound{
		ctx: ctx,
		server: net.Destination{
			Address: config.Address.AsAddress(),
			Port:    net.Port(config.Port),
			Network: net.Network_TCP,
		},
	}
	if C.Contains(shadowaead_2022.List, config.Method) {
		if config.Key == "" {
			return nil, newError("missing psk")
		}
		method, err := shadowaead_2022.NewWithPassword(config.Method, config.Key, nil)
		if err != nil {
			return nil, newError("create method").Base(err)
		}
		o.method = method
	} else {
		return nil, newError("unknown method ", config.Method)
	}
	if config.UdpOverTcp {
		o.uotClient = &uot.Client{Version: uint8(config.UdpOverTcpVersion)}
	}
	return o, nil
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var inboundConn net.Conn
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inboundConn = inbound.Conn
		inbound.SetCanSpliceCopy(3)
	}

	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	outbound.Name = "shadowsocks-2022"
	destination := outbound.Target
	network := destination.Network

	newError("tunneling request to ", destination, " via ", o.server.NetAddr()).WriteToLog(session.ExportIDToError(ctx))

	serverDestination := o.server
	if o.uotClient != nil {
		serverDestination.Network = net.Network_TCP
	} else {
		serverDestination.Network = network
	}
	connection, err := dialer.Dial(ctx, serverDestination)
	if err != nil {
		return newError("failed to connect to server").Base(err)
	}

	if session.TimeoutOnlyFromContext(ctx) {
		ctx, _ = context.WithCancel(context.Background())
	}

	if network == net.Network_TCP {
		serverConn := o.method.DialEarlyConn(connection, singbridge.ToSocksaddr(destination))
		var handshake bool
		if timeoutReader, isTimeoutReader := link.Reader.(buf.TimeoutReader); isTimeoutReader {
			mb, err := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 100)
			if err != nil && err != buf.ErrNotTimeoutReader && err != buf.ErrReadTimeout {
				return newError("read payload").Base(err)
			}
			_payload := B.StackNew()
			payload := C.Dup(_payload)
			defer payload.Release()
			for {
				payload.FullReset()
				nb, n := buf.SplitBytes(mb, payload.FreeBytes())
				if n > 0 {
					payload.Truncate(n)
					_, err = serverConn.Write(payload.Bytes())
					if err != nil {
						return newError("write payload").Base(err)
					}
					handshake = true
				}
				if nb.IsEmpty() {
					break
				} else {
					mb = nb
				}
			}
			runtime.KeepAlive(_payload)
		}
		if !handshake {
			_, err = serverConn.Write(nil)
			if err != nil {
				return newError("client handshake").Base(err)
			}
		}
		return singbridge.CopyConn(ctx, inboundConn, link, serverConn)
	} else {
		var packetConn N.PacketConn
		if pc, isPacketConn := inboundConn.(N.PacketConn); isPacketConn {
			packetConn = pc
		} else if nc, isNetPacket := inboundConn.(net.PacketConn); isNetPacket {
			packetConn = bufio.NewPacketConn(nc)
		} else {
			packetConn = &singbridge.PacketConnWrapper{
				Reader: link.Reader,
				Writer: link.Writer,
				Conn:   inboundConn,
				Dest:   destination,
			}
		}

		if o.uotClient != nil {
			uConn, err := o.uotClient.DialEarlyConn(o.method.DialEarlyConn(connection, uot.RequestDestination(o.uotClient.Version)), false, singbridge.ToSocksaddr(destination))
			if err != nil {
				return err
			}
			return singbridge.ReturnError(bufio.CopyPacketConn(ctx, packetConn, uConn))
		} else {
			serverConn := o.method.DialPacketConn(connection)
			return singbridge.ReturnError(bufio.CopyPacketConn(ctx, packetConn, serverConn))
		}
	}
}
