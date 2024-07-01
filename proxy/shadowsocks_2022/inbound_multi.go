package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/log"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/session"
	"github.com/GFW-knocker/Xray-core/common/singbridge"
	"github.com/GFW-knocker/Xray-core/common/uuid"
	"github.com/GFW-knocker/Xray-core/features/routing"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	A "github.com/sagernet/sing/common/auth"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func init() {
	common.Must(common.RegisterConfig((*MultiUserServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewMultiServer(ctx, config.(*MultiUserServerConfig))
	}))
}

type MultiUserInbound struct {
	sync.Mutex
	networks []net.Network
	users    []*User
	service  *shadowaead_2022.MultiService[int]
}

func NewMultiServer(ctx context.Context, config *MultiUserServerConfig) (*MultiUserInbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []net.Network{
			net.Network_TCP,
			net.Network_UDP,
		}
	}
	inbound := &MultiUserInbound{
		networks: networks,
		users:    config.Users,
	}
	if config.Key == "" {
		return nil, errors.New("missing key")
	}
	psk, err := base64.StdEncoding.DecodeString(config.Key)
	if err != nil {
		return nil, errors.New("parse config").Base(err)
	}
	service, err := shadowaead_2022.NewMultiService[int](config.Method, psk, 500, inbound, nil)
	if err != nil {
		return nil, errors.New("create service").Base(err)
	}

	for i, user := range config.Users {
		if user.Email == "" {
			u := uuid.New()
			user.Email = "unnamed-user-" + strconv.Itoa(i) + "-" + u.String()
		}
	}
	err = service.UpdateUsersWithPasswords(
		C.MapIndexed(config.Users, func(index int, it *User) int { return index }),
		C.Map(config.Users, func(it *User) string { return it.Key }),
	)
	if err != nil {
		return nil, errors.New("create service").Base(err)
	}

	inbound.service = service
	return inbound, nil
}

// AddUser implements proxy.UserManager.AddUser().
func (i *MultiUserInbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	i.Lock()
	defer i.Unlock()

	account := u.Account.(*MemoryAccount)
	if account.Email != "" {
		for idx := range i.users {
			if i.users[idx].Email == account.Email {
				return errors.New("User ", account.Email, " already exists.")
			}
		}
	}
	i.users = append(i.users, &User{
		Key:   account.Key,
		Email: account.Email,
		Level: account.Level,
	})

	// sync to multi service
	// Considering implements shadowsocks2022 in xray-core may have better performance.
	i.service.UpdateUsersWithPasswords(
		C.MapIndexed(i.users, func(index int, it *User) int { return index }),
		C.Map(i.users, func(it *User) string { return it.Key }),
	)

	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (i *MultiUserInbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	i.Lock()
	defer i.Unlock()

	idx := -1
	for ii, u := range i.users {
		if strings.EqualFold(u.Email, email) {
			idx = ii
			break
		}
	}

	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}

	ulen := len(i.users)

	i.users[idx] = i.users[ulen-1]
	i.users[ulen-1] = nil
	i.users = i.users[:ulen-1]

	// sync to multi service
	// Considering implements shadowsocks2022 in xray-core may have better performance.
	i.service.UpdateUsersWithPasswords(
		C.MapIndexed(i.users, func(index int, it *User) int { return index }),
		C.Map(i.users, func(it *User) string { return it.Key }),
	)

	return nil
}

func (i *MultiUserInbound) Network() []net.Network {
	return i.networks
}

func (i *MultiUserInbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022-multi"
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

func (i *MultiUserInbound) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	inbound := session.InboundFromContext(ctx)
	userInt, _ := A.UserFromContext[int](ctx)
	user := i.users[userInt]
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
	dispatcher := session.DispatcherFromContext(ctx)
	destination := singbridge.ToDestination(metadata.Destination, net.Network_TCP)
	if !destination.IsValid() {
		return errors.New("invalid destination")
	}

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	return singbridge.CopyConn(ctx, conn, link, conn)
}

func (i *MultiUserInbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	inbound := session.InboundFromContext(ctx)
	userInt, _ := A.UserFromContext[int](ctx)
	user := i.users[userInt]
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
	dispatcher := session.DispatcherFromContext(ctx)
	destination := singbridge.ToDestination(metadata.Destination, net.Network_UDP)
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	outConn := &singbridge.PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
	}
	return bufio.CopyPacketConn(ctx, conn, outConn)
}

func (i *MultiUserInbound) NewError(ctx context.Context, err error) {
	if E.IsClosed(err) {
		return
	}
	errors.LogWarning(ctx, err.Error())
}
