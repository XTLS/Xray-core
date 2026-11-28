package trojan

import (
	"context"
	"io"
	"maps"
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
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

func (s *Server) handleUDPPayload(ctx context.Context, sessionPolicy policy.Session, reader *PacketReader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	ctx, cancel := context.WithCancelCause(ctx)
	activity := signal.CancelAfterInactivity(ctx, func() { cancel(context.Canceled) }, sessionPolicy.Timeouts.ConnectionIdle)
	defer activity.SetTimeout(0)

	bufferPolicy := policy.BufferPolicyFromContext(ctx).PerConnection
	flow := &udpFlow{
		input:         udp.NewPacketInbox(bufferPolicy),
		writer:        PacketWriter{Writer: conn},
		cancel:        cancel,
		timer:         activity,
		responseLimit: int64(bufferPolicy),
	}
	flow.responseReady.L = &flow.responseMu
	carrierClosed := make(chan struct{})
	context.AfterFunc(ctx, func() {
		defer close(carrierClosed)
		flow.input.Close()
		flow.wakeReplies()
		conn.Close()
	})

	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		flow.sendReplies(ctx)
	}()

	// The carrier decoder retains complete frames while a route opens or
	// a sniff read times out. Activity is measured on the actual carrier.
	decoderDone := make(chan struct{})
	go func() {
		defer close(decoderDone)
		for ctx.Err() == nil {
			packets, err := reader.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(packets)
				if errors.Cause(err) == io.EOF {
					cancel(io.EOF)
				} else {
					cancel(errors.New("unexpected EOF").Base(err))
				}
				return
			}
			if packets.IsEmpty() {
				buf.ReleaseMulti(packets)
				continue
			}
			activity.Update()
			if err := flow.input.Put(ctx, packets); err != nil {
				cancel(err)
				return
			}
		}
	}()
	defer func() {
		cancel(context.Canceled)
		<-carrierClosed
		<-decoderDone
		<-senderDone
	}()

	var destination net.Destination
	for ctx.Err() == nil {
		first, err := flow.input.Take(ctx, nil)
		if err != nil {
			break
		}
		if ctx.Err() != nil {
			buf.ReleaseMulti(first)
			break
		}
		packetDestination := *first[0].UDP
		if !destination.IsValid() {
			destination = packetDestination
		}
		flow.dispatch(ctx, dispatcher, destination, packetDestination, first)
	}
	if cause := context.Cause(ctx); cause != io.EOF {
		return cause
	}
	return nil
}

type udpFlow struct {
	input  *udp.PacketInbox
	cancel context.CancelCauseFunc
	timer  *signal.ActivityTimer

	// The carrier sender drains replies independently of a shared outbound.
	writer        PacketWriter
	responseMu    sync.Mutex
	responseReady sync.Cond
	responses     buf.MultiBuffer
	responseBytes int64
	responseLimit int64
}

func (f *udpFlow) dispatch(ctx context.Context, dispatcher routing.Dispatcher, destination, firstDestination net.Destination, first buf.MultiBuffer) {
	inbound := session.InboundFromContext(ctx)
	if inbound.Source.IsValid() {
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   inbound.Source,
			To:     firstDestination,
			Status: log.AccessAccepted,
			Email:  inbound.User.Email,
		})
	}

	// DispatchLink mutates route and sniffing metadata for this leg.
	previous := session.OutboundsFromContext(ctx)
	outbounds := make([]*session.Outbound, len(previous))
	for i, outbound := range previous {
		value := *outbound
		outbounds[i] = &value
	}
	ctx = session.ContextWithOutbounds(ctx, outbounds)
	if content := session.ContentFromContext(ctx); content != nil {
		value := *content
		value.Attributes = maps.Clone(content.Attributes)
		ctx = session.ContextWithContent(ctx, &value)
	}

	ctx, cancel := context.WithCancel(ctx)
	route := &udpRoute{
		ctx:        ctx,
		cancel:     cancel,
		flow:       f,
		first:      first,
		lastSource: destination,
	}
	route.timer = signal.CancelAfterInactivity(ctx, route.Interrupt, time.Minute)
	defer route.timer.SetTimeout(0)
	f.input.AttachRoute(ctx)
	if ctx.Err() == nil {
		if err := dispatcher.DispatchLink(ctx, destination, &transport.Link{Reader: route, Writer: route}); err != nil {
			errors.LogInfoInner(ctx, err, "failed to dispatch UDP to ", destination)
		}
	}

	route.Interrupt()
	route.readMu.Lock()
	route.first = buf.ReleaseMulti(route.first)
	route.readMu.Unlock()
	f.input.RetireRoute()
}

type udpRoute struct {
	ctx    context.Context
	cancel context.CancelFunc
	flow   *udpFlow
	timer  *signal.ActivityTimer

	readMu         sync.Mutex
	first          buf.MultiBuffer
	primaryBound   bool
	uplinkCounters []stats.Counter
	lastSource     net.Destination // guarded by flow.responseMu
}

func (r *udpRoute) SetUplinkCounter(counter stats.Counter) {
	r.readMu.Lock()
	defer r.readMu.Unlock()

	if !r.primaryBound {
		r.primaryBound = true
		r.flow.input.BindUplinkCounter(r.ctx, counter)
		if counter != nil {
			counter.Add(int64(r.first.Len()))
		}
	} else if counter != nil {
		// Loopback can re-dispatch the same reader using the same counter.
		r.uplinkCounters = append(r.uplinkCounters, counter)
	}
}

func (r *udpRoute) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.read(nil)
}

func (r *udpRoute) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	return r.read(timer.C)
}

func (r *udpRoute) read(timeout <-chan time.Time) (buf.MultiBuffer, error) {
	r.readMu.Lock()
	defer r.readMu.Unlock()
	if r.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	packets := r.first
	if packets != nil {
		r.first = nil
	} else {
		var err error
		packets, err = r.flow.input.Take(r.ctx, timeout)
		if r.ctx.Err() != nil {
			buf.ReleaseMulti(packets)
			return nil, io.ErrClosedPipe
		}
		if err != nil {
			return nil, err
		}
	}
	size := int64(packets.Len())
	for _, counter := range r.uplinkCounters {
		counter.Add(size)
	}
	return packets, nil
}

func (r *udpRoute) WriteMultiBuffer(packets buf.MultiBuffer) error {
	f := r.flow
	f.responseMu.Lock()
	defer f.responseMu.Unlock()
	for r.ctx.Err() == nil && f.responseLimit >= 0 && f.responseBytes > f.responseLimit {
		f.responseReady.Wait()
	}
	if r.ctx.Err() != nil {
		buf.ReleaseMulti(packets)
		return io.ErrClosedPipe
	}
	r.timer.Update()
	for _, packet := range packets {
		if packet.UDP == nil {
			source := r.lastSource
			packet.UDP = &source
		} else {
			r.lastSource = *packet.UDP
		}
	}
	f.responseBytes += int64(packets.Len())
	if f.responses == nil {
		f.responses = packets
	} else {
		f.responses = append(f.responses, packets...)
	}
	f.responseReady.Broadcast()
	return nil
}

func (r *udpRoute) Interrupt() {
	r.cancel()
	r.flow.wakeReplies()
}

func (r *udpRoute) Close() error {
	r.Interrupt()
	return nil
}

func (f *udpFlow) wakeReplies() {
	f.responseMu.Lock()
	f.responseReady.Broadcast()
	f.responseMu.Unlock()
}

func (f *udpFlow) sendReplies(ctx context.Context) {
	defer func() {
		f.responseMu.Lock()
		f.responses = buf.ReleaseMulti(f.responses)
		f.responseMu.Unlock()
	}()
	for {
		f.responseMu.Lock()
		for len(f.responses) == 0 && ctx.Err() == nil {
			f.responseReady.Wait()
		}
		responses := f.responses
		if len(responses) == 0 || ctx.Err() != nil {
			f.responseMu.Unlock()
			return
		}
		f.responses, f.responseBytes = nil, 0
		f.responseReady.Broadcast()
		f.responseMu.Unlock()

		if err := f.writer.WriteMultiBuffer(responses); err != nil {
			errors.LogWarningInner(ctx, err, "failed to write response")
			f.cancel(err)
			return
		}
		f.timer.Update()
	}
}
