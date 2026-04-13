package shadowsocks_2022

import (
	"context"
	"strconv"
	"strings"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	A "github.com/sagernet/sing/common/auth"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/app/connectiontracker"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*RelayServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewRelayServer(ctx, config.(*RelayServerConfig))
	}))
}

type RelayInbound struct {
	networks      []net.Network
	destinations  []*RelayDestination
	service       *shadowaead_2022.RelayService[int]
	accessManager *connectiontracker.Manager
	connTracker   *connectiontracker.Tracker
}

func NewRelayServer(ctx context.Context, config *RelayServerConfig) (*RelayInbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []net.Network{
			net.Network_TCP,
			net.Network_UDP,
		}
	}

	var trackerManager *connectiontracker.Manager
	if err := core.RequireFeatures(ctx, func(trackerSvc connectiontracker.Feature) error {
		trackerManager = trackerSvc.Manager()
		return nil
	}); err != nil {
		return nil, err
	}
	if trackerManager == nil {
		return nil, errors.New("connection tracker feature is not available")
	}

	inbound := &RelayInbound{
		networks:      networks,
		destinations:  config.Destinations,
		accessManager: trackerManager,
		connTracker:   trackerManager.NewTracker(),
	}
	if !C.Contains(shadowaead_2022.List, config.Method) || !strings.Contains(config.Method, "aes") {
		return nil, errors.New("unsupported method ", config.Method)
	}
	service, err := shadowaead_2022.NewRelayServiceWithPassword[int](config.Method, config.Key, 500, inbound)
	if err != nil {
		return nil, errors.New("create service").Base(err)
	}

	for i, destination := range config.Destinations {
		if destination.Email == "" {
			u := uuid.New()
			destination.Email = "unnamed-destination-" + strconv.Itoa(i) + "-" + u.String()
		}
	}
	err = service.UpdateUsersWithPasswords(
		C.MapIndexed(config.Destinations, func(index int, it *RelayDestination) int { return index }),
		C.Map(config.Destinations, func(it *RelayDestination) string { return it.Key }),
		C.Map(config.Destinations, func(it *RelayDestination) M.Socksaddr {
			return singbridge.ToSocksaddr(net.Destination{
				Address: it.Address.AsAddress(),
				Port:    net.Port(it.Port),
			})
		}),
	)
	if err != nil {
		return nil, errors.New("create service").Base(err)
	}
	inbound.service = service
	return inbound, nil
}

func (i *RelayInbound) Network() []net.Network {
	return i.networks
}

func (i *RelayInbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022-relay"
	inbound.CanSpliceCopy = 3

	var metadata M.Metadata
	if inbound.Source.IsValid() {
		metadata.Source = M.ParseSocksaddr(inbound.Source.NetAddr())
	}

	ctx = session.ContextWithDispatcher(ctx, dispatcher)

	if network == net.Network_TCP {
		return singbridge.ReturnError(i.service.NewConnection(ctx, connection, metadata))
	} else {
		reader := buf.NewReader(connection)
		pc := &natPacketConn{connection}
		for {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(mb)
				return singbridge.ReturnError(err)
			}
			for _, buffer := range mb {
				packet := B.As(buffer.Bytes()).ToOwned()
				buffer.Release()
				err = i.service.NewPacket(ctx, pc, packet, metadata)
				if err != nil {
					packet.Release()
					buf.ReleaseMulti(mb)
					return err
				}
			}
		}
	}
}

func (i *RelayInbound) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	inbound := session.InboundFromContext(ctx)
	userInt, _ := A.UserFromContext[int](ctx)
	user := i.destinations[userInt]
	inbound.User = &protocol.MemoryUser{
		Email: user.Email,
		Level: uint32(user.Level),
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to tcp:", metadata.Destination)

	ctx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	if email := strings.ToLower(user.Email); email != "" {
		connID, connEntry := i.connTracker.RegisterWithMeta(email, connCancel, inbound.Tag, "shadowsocks-2022-relay")
		defer i.connTracker.Unregister(email, connID)
		conn = connectiontracker.WrapConn(conn, connEntry)
	}

	dispatcher := session.DispatcherFromContext(ctx)
	destination := singbridge.ToDestination(metadata.Destination, net.Network_TCP)
	if !destination.IsValid() {
		return errors.New("invalid destination")
	}

	var accessRecord *connectiontracker.AccessRecord
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil && i.accessManager != nil {
		accessRecord = i.accessManager.NewAccessRecord(accessMessage, connCancel)
		ctx = connectiontracker.ContextWithAccessRecord(ctx, accessRecord)
		defer i.accessManager.FinishAccessRecord(accessRecord)
	}
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		if accessRecord != nil {
			i.accessManager.AbortAccessRecord(accessRecord, err)
		}
		return err
	}
	link = connectiontracker.WrapAccessLink(link, accessRecord)
	if err := singbridge.CopyConn(ctx, nil, link, conn); err != nil {
		if accessRecord != nil {
			i.accessManager.AbortAccessRecord(accessRecord, err)
		}
		return err
	}
	return nil
}

func (i *RelayInbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	inbound := session.InboundFromContext(ctx)
	userInt, _ := A.UserFromContext[int](ctx)
	user := i.destinations[userInt]
	inbound.User = &protocol.MemoryUser{
		Email: user.Email,
		Level: uint32(user.Level),
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to udp:", metadata.Destination)

	ctx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	if email := strings.ToLower(user.Email); email != "" {
		connID, connEntry := i.connTracker.RegisterWithMeta(email, connCancel, inbound.Tag, "shadowsocks-2022-relay")
		defer i.connTracker.Unregister(email, connID)
		conn = connectiontracker.WrapPacketConn(conn, connEntry)
	}

	dispatcher := session.DispatcherFromContext(ctx)
	destination := singbridge.ToDestination(metadata.Destination, net.Network_UDP)
	var accessRecord *connectiontracker.AccessRecord
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil && i.accessManager != nil {
		accessRecord = i.accessManager.NewAccessRecord(accessMessage, connCancel)
		ctx = connectiontracker.ContextWithAccessRecord(ctx, accessRecord)
		defer i.accessManager.FinishAccessRecord(accessRecord)
	}
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		if accessRecord != nil {
			i.accessManager.AbortAccessRecord(accessRecord, err)
		}
		return err
	}
	link = connectiontracker.WrapAccessLink(link, accessRecord)
	outConn := &singbridge.PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
	}
	if err := bufio.CopyPacketConn(ctx, conn, outConn); err != nil {
		if accessRecord != nil {
			i.accessManager.AbortAccessRecord(accessRecord, err)
		}
		return err
	}
	return nil
}

func (i *RelayInbound) NewError(ctx context.Context, err error) {
	if E.IsClosed(err) {
		return
	}
	errors.LogWarning(ctx, err.Error())
}
