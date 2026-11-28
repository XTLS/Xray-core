package shadowsocks

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

func (s *Server) handleUDPPayload(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	ctx, cancel := context.WithCancel(ctx)
	inbound := *session.InboundFromContext(ctx)
	inbox := udp.NewPacketInbox(policy.BufferPolicyFromContext(ctx).PerConnection)
	closed := make(chan struct{})
	context.AfterFunc(ctx, func() {
		defer close(closed)
		inbox.Close()
		conn.Close()
	})
	started := make(chan udpAssociationStart)
	received := make(chan struct{})
	go func() {
		defer close(received)
		defer cancel()
		s.readUDPAssociation(ctx, conn, inbound, inbox, started)
	}()
	defer func() {
		cancel()
		<-closed
		<-received
	}()

	var first udpAssociationStart
	select {
	case first = <-started:
	case <-ctx.Done():
		return nil
	}
	inbound.User = first.user
	association := session.ContextWithInbound(ctx, &inbound)
	accessContext := func(dest net.Destination) context.Context {
		if inbound.Source.IsValid() {
			return log.ContextWithAccessMessage(association, &log.AccessMessage{
				From: inbound.Source, To: dest, Status: log.AccessAccepted, Email: inbound.User.Email,
			})
		}
		return association
	}
	target := first.dest
	dispatchUDPRoute(accessContext(target), conn, inbox, dispatcher, target, target, inbound.User, first.payload)
	for ctx.Err() == nil {
		first, err := inbox.Take(ctx, nil)
		if err != nil {
			break
		}
		firstTarget := *first[0].UDP
		dispatchUDPRoute(accessContext(firstTarget), conn, inbox, dispatcher, target, firstTarget, inbound.User, first)
	}
	return nil
}

type udpAssociationStart struct {
	user    *protocol.MemoryUser
	dest    net.Destination
	payload buf.MultiBuffer
}

func (s *Server) readUDPAssociation(ctx context.Context, conn stat.Connection, inbound session.Inbound, inbox *udp.PacketInbox, started chan<- udpAssociationStart) {
	reader := buf.NewPacketReader(conn)
	validator := s.validator
	user := inbound.User
	if user != nil {
		validator = new(Validator)
		_ = validator.Add(user)
	}
	first := true
	for ctx.Err() == nil {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			return
		}
		for i, payload := range mb {
			request, data, err := DecodeUDPPacket(validator, payload)
			if err != nil {
				if inbound.Source.IsValid() {
					errors.LogInfoInner(ctx, err, "dropping invalid UDP packet from: ", inbound.Source)
					log.Record(&log.AccessMessage{From: inbound.Source, Status: log.AccessRejected, Reason: err})
				}
				payload.Release()
				continue
			}
			if user == nil {
				user = request.User
				validator = new(Validator)
				_ = validator.Add(user)
			}
			destination := request.Destination()
			data.UDP = &destination
			errors.LogInfo(ctx, "tunnelling request to ", destination)
			if first {
				first = false
				start := udpAssociationStart{user: user, dest: destination}
				if data.IsEmpty() {
					data.Release()
				} else {
					start.payload = buf.MultiBuffer{data}
				}
				select {
				case started <- start:
				case <-ctx.Done():
					buf.ReleaseMulti(start.payload)
					buf.ReleaseMulti(mb[i+1:])
					return
				}
				continue
			}
			if data.IsEmpty() {
				data.Release()
				continue
			}
			if err := inbox.Put(ctx, buf.MultiBuffer{data}); err != nil {
				buf.ReleaseMulti(mb[i+1:])
				return
			}
		}
	}
}

func dispatchUDPRoute(ctx context.Context, conn stat.Connection, inbox *udp.PacketInbox, dispatcher routing.Dispatcher, target, replyTo net.Destination, user *protocol.MemoryUser, first buf.MultiBuffer) {
	routeCtx, cancel := context.WithCancel(udp.WithPacketRouteState(ctx))
	inbox.AttachRoute(routeCtx)
	reader := udp.NewDispatchPacketReader(routeCtx, cancel, inbox, first)
	timer := signal.CancelAfterInactivity(routeCtx, cancel, time.Minute)
	writer := &udpRouteWriter{ctx: routeCtx, conn: conn, fallback: replyTo, user: user, timer: timer, cancel: cancel}
	if routeCtx.Err() == nil {
		if err := dispatcher.DispatchLink(routeCtx, target, &transport.Link{Reader: reader, Writer: writer}); err != nil {
			errors.LogInfoInner(ctx, err, "failed to dispatch UDP to ", target)
		}
	}
	timer.SetTimeout(0)
	_ = reader.Close()
	writer.mu.Lock()
	writer.mu.Unlock()
	inbox.RetireRoute()
}

type udpRouteWriter struct {
	mu       sync.Mutex
	ctx      context.Context
	conn     stat.Connection
	fallback net.Destination
	user     *protocol.MemoryUser
	timer    *signal.ActivityTimer
	cancel   context.CancelFunc
}

func (w *udpRouteWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, payload := range mb {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		w.timer.Update()
		dest := w.fallback
		if payload.UDP != nil {
			dest = *payload.UDP
		}
		data, err := EncodeUDPPacket(&protocol.RequestHeader{User: w.user, Address: dest.Address, Port: dest.Port}, payload.Bytes())
		if err != nil {
			errors.LogWarningInner(w.ctx, err, "failed to encode UDP packet")
			continue
		}
		_, _ = w.conn.Write(data.Bytes())
		data.Release()
	}
	return nil
}

func (w *udpRouteWriter) Close() error {
	w.cancel()
	return nil
}

func (w *udpRouteWriter) Interrupt() {
	w.cancel()
}
