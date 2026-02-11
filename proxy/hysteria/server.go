package hysteria

import (
	"context"
	go_errors "errors"
	"math/rand"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
	cone          bool
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := account.NewValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get hysteria user").Base(err).AtError()
		}

		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
	}

	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	return s, nil
}

func (s *Server) HysteriaInboundValidator() *account.Validator {
	return s.validator
}

func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}

func (s *Server) RemoveUser(ctx context.Context, e string) error {
	return s.validator.Del(e)
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.GetCount()
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "hysteria"
	inbound.CanSpliceCopy = 3

	var useremail string
	var userlevel uint32
	type User interface{ User() *protocol.MemoryUser }
	if v, ok := conn.(User); ok {
		inbound.User = v.User()
		if inbound.User != nil {
			useremail = inbound.User.Email
			userlevel = inbound.User.Level
		}
	}

	iConn := stat.TryUnwrapStatsConn(conn)
	if _, ok := iConn.(*hysteria.InterUdpConn); ok {
		bufRead := make([]byte, MaxUDPSize)
		bufWrite := make([]byte, MaxUDPSize)
		df := &Defragger{}
		var firstDest *net.Destination

		sendMsg := func(msg *UDPMessage) error {
			msgN := msg.Serialize(bufWrite)
			if msgN < 0 {
				return nil
			}
			_, err := conn.Write(bufWrite[:msgN])
			return err
		}

		udpDispatcher := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
			addr := AddrFromContext(ctx)

			payload := packet.Payload
			if payload.UDP != nil {
				*addr = payload.UDP.NetAddr()
			}

			msg := &UDPMessage{
				SessionID: 0,
				PacketID:  0,
				FragID:    0,
				FragCount: 1,
				Addr:      *addr,
				Data:      payload.Bytes(),
			}

			err := sendMsg(msg)
			var errTooLarge *quic.DatagramTooLargeError
			if go_errors.As(err, &errTooLarge) {
				msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
				fMsgs := FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize))
				for _, fMsg := range fMsgs {
					err := sendMsg(&fMsg)
					if err != nil {
						break
					}
				}
			}

			payload.Release()
		})
		defer udpDispatcher.RemoveRay()

		for {
			n, err := conn.Read(bufRead)
			if err != nil {
				break
			}

			msg, err := ParseUDPMessage(bufRead[:n])
			if err != nil {
				continue
			}

			dfMsg := df.Feed(msg)
			if dfMsg == nil {
				continue
			}

			newCtx := ctx
			if inbound.Source.IsValid() {
				newCtx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
					From:   inbound.Source,
					To:     dfMsg.Addr,
					Status: log.AccessAccepted,
					Reason: "",
					Email:  useremail,
				})
			}
			errors.LogInfo(ctx, "tunnelling request to ", dfMsg.Addr)

			dest, _ := net.ParseDestination("udp:" + dfMsg.Addr)

			data := buf.New()
			data.Write(dfMsg.Data)
			data.UDP = &dest

			if !s.cone || firstDest == nil {
				firstDest = &dest
			}

			newCtx = ContextWithAddr(ctx, &dfMsg.Addr)
			udpDispatcher.Dispatch(newCtx, *firstDest, data)
		}

		return nil
	} else {
		sessionPolicy := s.policyManager.ForLevel(userlevel)
		conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake))

		addr, err := ReadTCPRequest(conn)
		if err != nil {
			log.Record(&log.AccessMessage{
				From:   conn.RemoteAddr(),
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
			return errors.New("failed to create request from: ", conn.RemoteAddr()).Base(err)
		}
		conn.SetReadDeadline(time.Time{})

		dest, _ := net.ParseDestination("tcp:" + addr)
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     dest,
			Status: log.AccessAccepted,
			Reason: "",
			Email:  useremail,
		})
		errors.LogInfo(ctx, "tunnelling request to ", dest)

		sessionPolicy = s.policyManager.ForLevel(userlevel)
		ctx, cancel := context.WithCancel(ctx)
		timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

		ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
		link, err := dispatcher.Dispatch(ctx, dest)
		if err != nil {
			return err
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
			err := WriteTCPResponse(bufferedWriter, true, "")
			if err != nil {
				return errors.New("failed to write response").Base(err)
			}

			if err := bufferedWriter.SetBuffered(false); err != nil {
				return err
			}

			if err := buf.Copy(link.Reader, bufferedWriter, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all TCP response").Base(err)
			}

			return nil
		}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

			if err := buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all TCP request").Base(err)
			}

			return nil
		}

		requestDoneAndCloseWriter := task.OnSuccess(requestDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			return errors.New("connection ends").Base(err)
		}

		return nil
	}
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type key int

const (
	addr key = iota
)

func ContextWithAddr(ctx context.Context, v *string) context.Context {
	return context.WithValue(ctx, addr, v)
}

func AddrFromContext(ctx context.Context) *string {
	v, _ := ctx.Value(addr).(*string)
	return v
}
