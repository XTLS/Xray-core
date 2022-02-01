package quic

import (
	"context"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type sessionContext struct {
	rawConn *sysConn
	session quic.Session
}

var errSessionClosed = newError("session closed")

func (c *sessionContext) openStream(destAddr net.Addr) (*interConn, error) {
	if !isActive(c.session) {
		return nil, errSessionClosed
	}

	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, err
	}

	conn := &interConn{
		stream: stream,
		local:  c.session.LocalAddr(),
		remote: destAddr,
	}

	return conn, nil
}

type clientSessions struct {
	access   sync.Mutex
	sessions map[net.Destination][]*sessionContext
	cleanup  *task.Periodic
}

func isActive(s quic.Session) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func removeInactiveSessions(sessions []*sessionContext) []*sessionContext {
	activeSessions := make([]*sessionContext, 0, len(sessions))
	for i, s := range sessions {
		if isActive(s.session) {
			activeSessions = append(activeSessions, s)
			continue
		}

		newError("closing quic session at index: ", i).WriteToLog()
		if err := s.session.CloseWithError(0, ""); err != nil {
			newError("failed to close session").Base(err).WriteToLog()
		}
		if err := s.rawConn.Close(); err != nil {
			newError("failed to close raw connection").Base(err).WriteToLog()
		}
	}

	if len(activeSessions) < len(sessions) {
		newError("active quic session reduced from ", len(sessions), " to ", len(activeSessions)).WriteToLog()
		return activeSessions
	}

	return sessions
}

func (s *clientSessions) cleanSessions() error {
	s.access.Lock()
	defer s.access.Unlock()

	if len(s.sessions) == 0 {
		return nil
	}

	newSessionMap := make(map[net.Destination][]*sessionContext)

	for dest, sessions := range s.sessions {
		sessions = removeInactiveSessions(sessions)
		if len(sessions) > 0 {
			newSessionMap[dest] = sessions
		}
	}

	s.sessions = newSessionMap
	return nil
}

func (s *clientSessions) openConnection(ctx context.Context, destAddr net.Addr, config *Config, tlsConfig *tls.Config, sockopt *internet.SocketConfig) (stat.Connection, error) {
	s.access.Lock()
	defer s.access.Unlock()

	if s.sessions == nil {
		s.sessions = make(map[net.Destination][]*sessionContext)
	}

	dest := net.DestinationFromAddr(destAddr)

	var sessions []*sessionContext
	if s, found := s.sessions[dest]; found {
		sessions = s
	}

	if len(sessions) > 0 {
		s := sessions[len(sessions)-1]
		if isActive(s.session) {
			conn, err := s.openStream(destAddr)
			if err == nil {
				return conn, nil
			}
			newError("failed to openStream: ").Base(err).WriteToLog()
		} else {
			newError("current quic session is not active!").WriteToLog()
		}
	}

	sessions = removeInactiveSessions(sessions)
	newError("dialing quic to ", dest).WriteToLog()
	rawConn, err := internet.DialSystem(ctx, dest, sockopt)
	if err != nil {
		return nil, newError("failed to dial to dest: ", err).AtWarning().Base(err)
	}

	quicConfig := &quic.Config{
		ConnectionIDLength: 12,
		KeepAlive:          false,
	}

	udpConn, _ := rawConn.(*net.UDPConn)
	if udpConn == nil {
		udpConn = rawConn.(*internet.PacketConnWrapper).Conn.(*net.UDPConn)
	}
	conn, err := wrapSysConn(udpConn, config)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	session, err := quic.DialContext(context.Background(), conn, destAddr, "", tlsConfig.GetTLSConfig(tls.WithDestination(dest)), quicConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	context := &sessionContext{
		session: session,
		rawConn: conn,
	}
	s.sessions[dest] = append(sessions, context)
	return context.openStream(destAddr)
}

var client clientSessions

func init() {
	client.sessions = make(map[net.Destination][]*sessionContext)
	client.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  client.cleanSessions,
	}
	common.Must(client.cleanup.Start())
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:    internalDomain,
			AllowInsecure: true,
		}
	}

	var destAddr *net.UDPAddr
	if dest.Address.Family().IsIP() {
		destAddr = &net.UDPAddr{
			IP:   dest.Address.IP(),
			Port: int(dest.Port),
		}
	} else {
		addr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
		if err != nil {
			return nil, err
		}
		destAddr = addr
	}

	config := streamSettings.ProtocolSettings.(*Config)

	return client.openConnection(ctx, destAddr, config, tlsConfig, streamSettings.SocketSettings)
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
