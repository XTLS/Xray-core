package hysteria

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
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
		buf := make([]byte, MaxUDPSize)
		df := &Defragger{}
		var firstMsg *UDPMessage

		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}

			msg, err := ParseUDPMessage(buf[:n])
			if err != nil {
				continue
			}

			dfMsg := df.Feed(msg)
			if dfMsg == nil {
				continue
			}

			firstMsg = dfMsg
			break
		}

		reader := &UDPReader{
			Reader:   conn,
			buf:      buf,
			df:       df,
			firstMsg: firstMsg,
		}

		writer := &UDPWriter{
			Writer: conn,
			buf:    make([]byte, MaxUDPSize),
			addr:   firstMsg.Addr,
		}

		dest := common.Must2(net.ParseDestination("udp:" + firstMsg.Addr))

		return dispatcher.DispatchLink(ctx, dest, &transport.Link{
			Reader: reader,
			Writer: writer,
		})
	} else {
		sessionPolicy := s.policyManager.ForLevel(userlevel)
		common.Must(conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)))
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
		common.Must(conn.SetReadDeadline(time.Time{}))

		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		err = WriteTCPResponse(bufferedWriter, true, "")
		if err != nil {
			return errors.New("failed to write response").Base(err)
		}
		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}

		dest := common.Must2(net.ParseDestination("tcp:" + addr))
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     dest,
			Status: log.AccessAccepted,
			Reason: "",
			Email:  useremail,
		})
		errors.LogInfo(ctx, "tunnelling request to ", dest)

		return dispatcher.DispatchLink(ctx, dest, &transport.Link{
			Reader: buf.NewReader(conn),
			Writer: bufferedWriter,
		})
	}
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
