package udp

import (
	"context"
	"io"
	"maps"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/stats"
)

// WithPacketRouteState gives each routed packet flow private sniffing and outbound state.
func WithPacketRouteState(ctx context.Context) context.Context {
	if previous := session.OutboundsFromContext(ctx); len(previous) > 0 {
		outbounds := make([]*session.Outbound, len(previous))
		for i, previous := range previous {
			outbound := *previous
			outbounds[i] = &outbound
		}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	if previous := session.ContentFromContext(ctx); previous != nil {
		content := *previous
		content.Attributes = maps.Clone(previous.Attributes)
		ctx = session.ContextWithContent(ctx, &content)
	}
	return ctx
}

// DispatchPacketReader feeds a single route with the association's decoded datagrams.
type DispatchPacketReader struct {
	ctx    context.Context
	cancel context.CancelFunc
	input  *PacketInbox

	mu       sync.Mutex
	first    buf.MultiBuffer
	bound    bool
	counters []stats.Counter
}

func NewDispatchPacketReader(ctx context.Context, cancel context.CancelFunc, input *PacketInbox, first buf.MultiBuffer) *DispatchPacketReader {
	return &DispatchPacketReader{ctx: ctx, cancel: cancel, input: input, first: first}
}

func (r *DispatchPacketReader) SetUplinkCounter(counter stats.Counter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.bound {
		r.bound = true
		r.input.BindUplinkCounter(r.ctx, counter)
		if counter != nil {
			counter.Add(int64(r.first.Len()))
		}
	} else if counter != nil {
		r.counters = append(r.counters, counter)
	}
}

func (r *DispatchPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.read(nil)
}

func (r *DispatchPacketReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	return r.read(timer.C)
}

func (r *DispatchPacketReader) read(timeout <-chan time.Time) (buf.MultiBuffer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	packets := r.first
	if packets != nil {
		r.first = nil
	} else {
		var err error
		packets, err = r.input.Take(r.ctx, timeout)
		if r.ctx.Err() != nil {
			buf.ReleaseMulti(packets)
			return nil, io.ErrClosedPipe
		}
		if err != nil {
			return nil, err
		}
	}
	size := int64(packets.Len())
	for _, counter := range r.counters {
		counter.Add(size)
	}
	return packets, nil
}

func (r *DispatchPacketReader) Interrupt() {
	r.cancel()
}

// Close cancels pending reads and releases the first record if it was unconsumed.
func (r *DispatchPacketReader) Close() error {
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.first = buf.ReleaseMulti(r.first)
	return nil
}
