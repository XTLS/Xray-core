package shadowsocks_2022

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func (s *ServerUDPSession) UpdateConn(conn stat.Connection) {
	if s.currentConn.Load() == nil {
		s.currentConn.Store(conn)
	}
	if s.timer != nil {
		s.timer.Update()
	}
}

func (s *ServerUDPSession) WriteToClient(b []byte) error {
	connVal := s.currentConn.Load()
	if connVal == nil {
		return errors.New("client connection closed")
	}
	conn, ok := connVal.(stat.Connection)
	if !ok || conn == nil {
		return errors.New("client connection closed")
	}
	_, err := conn.Write(b)
	return err
}

func (s *ServerUDPSession) Close() {
	if s.timer != nil {
		s.timer.SetTimeout(0)
	}
	if link := s.link.Load(); link != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
}

func (s *ServerUDPSession) EnsureLink(
	ctx context.Context,
	conn stat.Connection,
	dest net.Destination,
	dispatcher routing.Dispatcher,
	policyManager policy.Manager,
	responseEncoder func(dest net.Destination, payload []byte) ([]byte, error),
) (*transport.Link, error) {
	s.UpdateConn(conn)

	if link := s.link.Load(); link != nil {
		return link, nil
	}

	s.Lock()
	defer s.Unlock()

	if link := s.link.Load(); link != nil {
		return link, nil
	}

	sessCtx, cancel := context.WithCancel(ctx)
	inbound := session.InboundFromContext(sessCtx)
	if inbound != nil && s.User != nil {
		inbound.User = s.User
	}
	var email string
	var level uint32
	if s.User != nil {
		email = s.User.Email
		level = s.User.Level
	}
	sessCtx = log.ContextWithAccessMessage(sessCtx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  email,
	})

	link, err := dispatcher.Dispatch(sessCtx, dest)
	if err != nil {
		cancel()
		return nil, err
	}

	s.link.Store(link)
	sessionPolicy := policyManager.ForLevel(level)
	s.timer = signal.CancelAfterInactivity(sessCtx, func() {
		if s.manager != nil {
			s.manager.Delete(s.SessionID)
		}
		s.Close()
		cancel()
	}, sessionPolicy.Timeouts.ConnectionIdle)

	go handleUDPResponse(s, link, dest, responseEncoder)
	return link, nil
}

// ResetTCPConn sets SO_LINGER to 0 per SIP022 §3.1.4 to consistently send RST on close
// when handshake or header validation fails.
func ResetTCPConn(conn net.Conn) {
	rawConn, _, _ := proxy.UnwrapRawConn(conn)
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
}

func handleUDPResponse(s *ServerUDPSession, link *transport.Link, fallbackDest net.Destination, encode func(dest net.Destination, payload []byte) ([]byte, error)) {
	defer func() {
		if s.timer != nil {
			s.timer.SetTimeout(0)
		}
	}()
	for {
		resMb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return
		}
		if s.timer != nil {
			s.timer.Update()
		}
		for i, rb := range resMb {
			b := rb.Bytes()
			if encode != nil {
				replyDest := fallbackDest
				if rb.UDP != nil {
					replyDest = *rb.UDP
				}
				encPacket, err := encode(replyDest, b)
				rb.Release()
				if err != nil {
					continue
				}
				if err := s.WriteToClient(encPacket); err != nil {
					buf.ReleaseMulti(resMb[i+1:])
					return
				}
			} else {
				err := s.WriteToClient(b)
				rb.Release()
				if err != nil {
					buf.ReleaseMulti(resMb[i+1:])
					return
				}
			}
		}
	}
}

const (
	HeaderTypeClient              = 0
	HeaderTypeServer              = 1
	MaxPaddingLength              = 900
	PacketNonceSize               = 24
	MaxPacketSize                 = 65535
	RequestHeaderFixedChunkLength = 1 + 8 + 2 // Type (1B) + Timestamp (8B) + VarHeaderLen (2B)
	PacketMinimalHeaderSize       = 30
	StreamNonceSize               = 12
	AESBlockSize                  = 16
	AEADTagSize                   = 16
)

var zeroPadding [MaxPaddingLength]byte

const (
	MethodAES128GCM        = "2022-blake3-aes-128-gcm"
	MethodAES256GCM        = "2022-blake3-aes-256-gcm"
	MethodChaCha20Poly1305 = "2022-blake3-chacha20-poly1305"
)

var (
	ErrBadKey            = errors.New("bad key")
	ErrBadHeaderType     = errors.New("bad header type")
	ErrBadTimestamp      = errors.New("bad timestamp")
	ErrSaltNotUnique     = errors.New("salt not unique")
	ErrPacketIdNotUnique = errors.New("packet id not unique")
	ErrPacketTooShort    = errors.New("packet too short")
	ErrPacketTooLarge    = errors.New("packet too large")
	ErrNoPadding         = errors.New("bad request: missing payload or padding")
	ErrInvalidRequest    = errors.New("invalid request")
)
