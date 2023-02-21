package shadowtls

import (
	"context"
	"os"

	"github.com/sagernet/sing-shadowtls"
	sing_common "github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Inbound struct {
	service        *shadowtls.Service
	inboundManager inbound.Manager
	detour         string
}

func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	v := core.MustFromContext(ctx)
	inbound := &Inbound{
		inboundManager: v.GetFeature(inbound.ManagerType()).(inbound.Manager),
		detour:         config.Detour,
	}
	var handshakeForServerName map[string]shadowtls.HandshakeConfig
	if config.Version > 1 {
		handshakeForServerName = make(map[string]shadowtls.HandshakeConfig)
		for serverName, serverConfig := range config.HandshakeForServerName {
			handshakeForServerName[serverName] = shadowtls.HandshakeConfig{
				Server: singbridge.ToSocksaddr(net.Destination{
					Address: serverConfig.Address.AsAddress(),
					Port:    net.Port(serverConfig.Port),
				}),
				Dialer: N.SystemDialer,
			}
		}
	}
	service, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version:  int(config.Version),
		Password: config.Password,
		Users: sing_common.Map(config.Users, func(it *User) shadowtls.User {
			return shadowtls.User{
				Name:     it.Email,
				Password: it.Password,
			}
		}),
		Handshake: shadowtls.HandshakeConfig{
			Server: singbridge.ToSocksaddr(net.Destination{
				Address: config.Handshake.Address.AsAddress(),
				Port:    net.Port(config.Handshake.Port),
			}),
			Dialer: N.SystemDialer,
		},
		HandshakeForServerName: handshakeForServerName,
		StrictMode:             config.StrictMode,
		Handler:                inbound,
		Logger:                 singbridge.NewLogger(newError),
	})
	if err != nil {
		return nil, E.Cause(err, "create service")
	}
	inbound.service = service
	return inbound, nil
}

func (i *Inbound) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	var metadata M.Metadata
	if inbound.Source.IsValid() {
		metadata.Source = M.ParseSocksaddr(inbound.Source.NetAddr())
	}
	ctx = session.ContextWithDispatcher(ctx, dispatcher)
	return singbridge.ReturnError(i.service.NewConnection(ctx, connection, metadata))
}

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	inboundHandler, err := i.inboundManager.GetHandler(ctx, i.detour)
	if err != nil {
		return E.Cause(err, "detour not found")
	}

	inboundWrapper, loaded := inboundHandler.(proxy.GetInbound)
	if !loaded {
		return newError("can't get inbound proxy from handler.")
	}

	inboundDetour := inboundWrapper.GetInbound()

	email, _ := auth.UserFromContext[string](ctx)
	inbound := session.InboundFromContext(ctx)
	inbound.User = &protocol.MemoryUser{
		Email: email,
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  email,
	})
	newError("tunnelling request to detour").WriteToLog(session.ExportIDToError(ctx))
	return inboundDetour.Process(ctx, net.Network_TCP, conn, session.DispatcherFromContext(ctx))
}

func (i *Inbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return os.ErrInvalid
}

func (i *Inbound) NewError(ctx context.Context, err error) {
	if E.IsClosed(err) {
		return
	}
	newError(err).AtWarning().WriteToLog()
}
