package shadowsocks_2022

import (
	"context"
	"strings"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
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
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Inbound struct {
	networks      []net.Network
	service       shadowsocks.Service
	email         string
	level         int
	accessManager *connectiontracker.Manager
	connTracker   *connectiontracker.Tracker
}

func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
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

	inbound := &Inbound{
		networks:      networks,
		email:         config.Email,
		level:         int(config.Level),
		accessManager: trackerManager,
		connTracker:   trackerManager.NewTracker(),
	}
	if !C.Contains(shadowaead_2022.List, config.Method) {
		return nil, errors.New("unsupported method ", config.Method)
	}
	service, err := shadowaead_2022.NewServiceWithPassword(config.Method, config.Key, 500, inbound, nil)
	if err != nil {
		return nil, errors.New("create service").Base(err)
	}
	inbound.service = service
	return inbound, nil
}

func (i *Inbound) Network() []net.Network {
	return i.networks
}

func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022"
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

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	inbound := session.InboundFromContext(ctx)
	inbound.User = &protocol.MemoryUser{
		Email: i.email,
		Level: uint32(i.level),
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  i.email,
	})
	errors.LogInfo(ctx, "tunnelling request to tcp:", metadata.Destination)

	ctx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	if email := strings.ToLower(i.email); email != "" {
		connID, connEntry := i.connTracker.RegisterWithMeta(email, connCancel, inbound.Tag, "shadowsocks-2022")
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

func (i *Inbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	inbound := session.InboundFromContext(ctx)
	inbound.User = &protocol.MemoryUser{
		Email: i.email,
		Level: uint32(i.level),
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  i.email,
	})
	errors.LogInfo(ctx, "tunnelling request to udp:", metadata.Destination)

	ctx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	if email := strings.ToLower(i.email); email != "" {
		connID, connEntry := i.connTracker.RegisterWithMeta(email, connCancel, inbound.Tag, "shadowsocks-2022")
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

func (i *Inbound) NewError(ctx context.Context, err error) {
	if E.IsClosed(err) {
		return
	}
	errors.LogWarning(ctx, err.Error())
}

type natPacketConn struct {
	net.Conn
}

func (c *natPacketConn) ReadPacket(buffer *B.Buffer) (addr M.Socksaddr, err error) {
	_, err = buffer.ReadFrom(c)
	return
}

func (c *natPacketConn) WritePacket(buffer *B.Buffer, addr M.Socksaddr) error {
	_, err := buffer.WriteTo(c)
	return err
}
