package shadowsocks_2022

import (
	"context"
	"reflect"
	"sync"
	"time"

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
	"github.com/xtls/xray-core/transport/internet/udp"
)

type udpSessionPeer struct {
	conn stat.Connection
}

func (s *ServerUDPSession) bindPeer(conn stat.Connection) {
	if peer := s.currentConn; peer != nil && reflect.ValueOf(conn).Kind() == reflect.Pointer && peer.conn == conn {
		return
	}
	s.currentConn = &udpSessionPeer{conn: conn}
}

func (s *ServerUDPSession) WriteToClient(b []byte) error {
	s.Lock()
	peer := s.currentConn
	s.Unlock()
	if peer == nil {
		return errors.New("client connection closed")
	}
	_, err := peer.conn.Write(b)
	if err == nil {
		return nil
	}

	// This packet was offered to the old peer before reattachment. A later
	// failure on that socket must neither replay it nor retire the new peer.
	s.Lock()
	if s.currentConn != peer {
		s.Unlock()
		return nil
	}
	s.closeLocked()
	return err
}

func (s *ServerUDPSession) Close() {
	s.Lock()
	s.closeLocked()
}

func (s *ServerUDPSession) expire(before int64) {
	s.Lock()
	if s.LastActive.Load() >= before {
		s.Unlock()
		return
	}
	s.closeLocked()
}

// closeLocked retires only this session and releases the lock before waking I/O.
func (s *ServerUDPSession) closeLocked() {
	if s.closed {
		s.Unlock()
		return
	}
	s.closed = true
	s.currentConn = nil
	route := s.route
	if s.manager != nil {
		s.manager.sessions.CompareAndDelete(s.SessionID, s)
	}
	s.Unlock()

	if route != nil {
		route.cancel()
		route.input.Close()
		route.timer.SetTimeout(0)
	}
}

func (s *ServerUDPSession) dispatchPacket(
	ctx context.Context,
	conn stat.Connection,
	dest net.Destination,
	dispatcher routing.Dispatcher,
	policyManager policy.Manager,
	encode func(net.Destination, []byte) ([]byte, error),
	packet *buf.Buffer,
) {
	s.Lock()
	if s.closed {
		s.Unlock()
		packet.Release()
		return
	}
	s.bindPeer(conn)
	s.LastActive.Store(time.Now().Unix())
	if route := s.route; route != nil {
		route.timer.Update()
		s.Unlock()
		_ = route.input.Put(route.ctx, buf.MultiBuffer{packet})
		return
	}

	// An authenticated session keeps its route across physical UDP peers.
	sessCtx, cancel := context.WithCancel(udp.WithPacketRouteState(context.WithoutCancel(ctx)))
	if inbound := session.InboundFromContext(sessCtx); inbound != nil {
		newInbound := *inbound
		if s.User != nil {
			newInbound.User = s.User
		}
		sessCtx = session.ContextWithInbound(sessCtx, &newInbound)
	}
	var email string
	var level uint32
	if s.User != nil {
		email = s.User.Email
		level = s.User.Level
	}
	sessCtx = log.ContextWithAccessMessage(sessCtx, &log.AccessMessage{
		From: conn.RemoteAddr(), To: dest, Status: log.AccessAccepted, Email: email,
	})
	input := udp.NewPacketInbox(policy.BufferPolicyFromContext(sessCtx).PerConnection)
	input.AttachRoute(sessCtx)
	route := &udpSessionRoute{
		ctx: sessCtx, cancel: cancel, input: input,
		timer:   signal.CancelAfterInactivity(sessCtx, cancel, policyManager.ForLevel(level).Timeouts.ConnectionIdle),
		session: s, fallback: dest, encode: encode,
	}
	s.route = route
	s.Unlock()

	context.AfterFunc(sessCtx, input.Close)
	// Seed the association before the routed reader is started. This prevents
	// the first packet from lagging behind packets from a concurrent reattachment.
	reader := udp.NewDispatchPacketReader(sessCtx, cancel, input, buf.MultiBuffer{packet})
	go func() {
		defer s.Close()
		defer reader.Close()
		if sessCtx.Err() == nil {
			if err := dispatcher.DispatchLink(sessCtx, dest, &transport.Link{Reader: reader, Writer: route}); err != nil {
				errors.LogInfoInner(sessCtx, err, "connection ends")
			}
		}
	}()
}

type udpSessionRoute struct {
	ctx      context.Context
	cancel   context.CancelFunc
	input    *udp.PacketInbox
	timer    *signal.ActivityTimer
	session  *ServerUDPSession
	fallback net.Destination
	encode   func(net.Destination, []byte) ([]byte, error)
	writeMu  sync.Mutex
}

func (r *udpSessionRoute) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	for _, packet := range mb {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		r.timer.Update()
		data := packet.Bytes()
		if r.encode != nil {
			dest := r.fallback
			if packet.UDP != nil {
				dest = *packet.UDP
			}
			var err error
			data, err = r.encode(dest, data)
			if err != nil {
				continue
			}
			r.session.LastActive.Store(time.Now().Unix())
		}
		if err := r.session.WriteToClient(data); err != nil {
			return err
		}
	}
	return nil
}

func (r *udpSessionRoute) Close() error {
	r.cancel()
	return nil
}

func (r *udpSessionRoute) Interrupt() {
	_ = r.Close()
}

// ResetTCPConn sets SO_LINGER to 0 per SIP022 §3.1.4 to consistently send RST on close
// when handshake or header validation fails.
func ResetTCPConn(conn net.Conn) {
	rawConn, _, _ := proxy.UnwrapRawConn(conn)
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
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
