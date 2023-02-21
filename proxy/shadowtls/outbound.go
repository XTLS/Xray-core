package shadowtls

import (
	"context"
	"crypto/tls"

	"github.com/sagernet/sing-shadowtls"
	"github.com/xtls/xray-core/common"
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
	ctx          context.Context
	clientConfig shadowtls.ClientConfig
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	return &Outbound{
		ctx: ctx,
		clientConfig: shadowtls.ClientConfig{
			Version:  int(config.Version),
			Password: config.Password,
			Server: singbridge.ToSocksaddr(net.Destination{
				Address: config.Address.AsAddress(),
				Port:    net.Port(config.Port),
			}),
			Logger: singbridge.NewLogger(newError),
		},
	}, nil
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var inboundConn net.Conn
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inboundConn = inbound.Conn
	}

	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	destination := outbound.Target

	if destination.Network != net.Network_TCP {
		return newError("only TCP is supported")
	}

	newError("tunneling request to ", destination, " via ", o.clientConfig.Server).WriteToLog(session.ExportIDToError(ctx))

	var client *shadowtls.Client
	clientConfig := o.clientConfig
	if clientConfig.Version == 3 {
		clientConfig.Dialer = singbridge.NewTLSDialer(dialer, func(conn net.Conn, config *tls.Config) net.Conn {
			client.SetTLSConfig(config)
			return conn
		})
	} else {
		clientConfig.Dialer = singbridge.NewDialer(dialer)
	}
	var err error
	client, err = shadowtls.NewClient(clientConfig)
	if err != nil {
		return newError("failed to create client").Base(err)
	}

	conn, err := client.DialContext(ctx)
	if err != nil {
		return newError("failed to connect to server").Base(err)
	}

	return singbridge.CopyConn(ctx, inboundConn, link, conn)
}
