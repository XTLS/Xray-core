package udp

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
)

// PacketInbox retains decoded input while an association's selected route opens.
// The association owns its socket and the inbox. Routes only consume packets.
type PacketInbox struct {
	mu     sync.Mutex
	room   sync.Cond
	ready  *signal.Notifier
	queued []buf.MultiBuffer
	bytes  int64
	limit  int64
	closed bool

	active        context.Context
	owned         int // queued prefix admitted to the active route
	uplinkCounter stats.Counter
	uplinkPending int64
	uplinkBound   bool
}

func NewPacketInbox(limit int32) *PacketInbox {
	inbox := &PacketInbox{limit: int64(limit), ready: signal.NewNotifier()}
	inbox.room.L = &inbox.mu
	return inbox
}

// Put takes ownership of one decoded record, including on cancellation.
func (p *PacketInbox) Put(ctx context.Context, packet buf.MultiBuffer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	size := int64(packet.Len())
	owner := p.active
	if !p.closed && ctx.Err() == nil && owner != nil && owner.Err() == nil {
		p.countAttempt(size)
	} else {
		owner = nil
	}
	// Keep the existing soft byte limit. Zero still admits a record and a
	// negative limit explicitly permits unlimited buffering.
	var stopWakeup func() bool
	for !p.closed && ctx.Err() == nil && (owner == nil || owner.Err() == nil) && p.limit >= 0 && p.bytes > p.limit {
		if stopWakeup == nil {
			stopWakeup = context.AfterFunc(ctx, func() {
				p.mu.Lock()
				p.room.Broadcast()
				p.mu.Unlock()
			})
			defer stopWakeup()
		}
		p.room.Wait()
	}
	if err := ctx.Err(); err != nil {
		buf.ReleaseMulti(packet)
		return err
	}
	if p.closed {
		buf.ReleaseMulti(packet)
		return io.ErrClosedPipe
	}
	ownedByRoute := owner != nil
	if ownedByRoute {
		if owner.Err() != nil {
			buf.ReleaseMulti(packet)
			return nil
		}
	} else if p.active != nil && p.active.Err() == nil {
		ownedByRoute = true
		p.countAttempt(size)
	}
	// The route decision above is the admission point. Cancellation after
	// it must not turn an old route's record into input for its replacement.
	p.queued = append(p.queued, packet)
	p.bytes += size
	if ownedByRoute {
		p.owned++
	}
	p.ready.Signal()
	return nil
}

func (p *PacketInbox) AttachRoute(ctx context.Context) {
	p.mu.Lock()
	p.active = ctx
	if ctx.Err() == nil {
		p.owned = len(p.queued)
		p.uplinkPending = p.bytes
	}
	p.mu.Unlock()
}

// BindUplinkCounter counts attempted input at the association's first dispatch.
// Nested dispatchers count the records they receive from that route's reader.
func (p *PacketInbox) BindUplinkCounter(ctx context.Context, counter stats.Counter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active != ctx || p.uplinkBound {
		return
	}
	p.uplinkCounter = counter
	p.uplinkBound = true
	if counter != nil && p.uplinkPending != 0 {
		counter.Add(p.uplinkPending)
	}
	p.uplinkPending = 0
}

func (p *PacketInbox) countAttempt(size int64) {
	if !p.uplinkBound {
		p.uplinkPending += size
	} else if p.uplinkCounter != nil {
		p.uplinkCounter.Add(size)
	}
}

// RetireRoute releases queued records admitted to the ending route. Records
// received after that route was canceled still belong to the association.
func (p *PacketInbox) RetireRoute() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, packet := range p.queued[:p.owned] {
		p.bytes -= int64(packet.Len())
		buf.ReleaseMulti(packet)
	}
	clear(p.queued[:p.owned])
	p.queued = p.queued[p.owned:]
	p.owned = 0
	p.active = nil
	p.uplinkCounter = nil
	p.uplinkPending = 0
	p.uplinkBound = false
	p.room.Broadcast()
}

// Take gives the association one record to select a route. That route then
// takes all its available records together, retaining their packet boundaries.
func (p *PacketInbox) Take(ctx context.Context, timeout <-chan time.Time) (buf.MultiBuffer, error) {
	for {
		p.mu.Lock()
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			return nil, err
		}
		if p.closed {
			p.mu.Unlock()
			return nil, io.ErrClosedPipe
		}
		if len(p.queued) != 0 {
			records := 1
			if p.active == ctx && p.owned > 1 {
				records = p.owned
			}
			batch := p.queued[0]
			for _, packet := range p.queued[1:records] {
				batch, _ = buf.MergeMulti(batch, packet)
			}
			clear(p.queued[:records])
			p.queued = p.queued[records:]
			p.bytes -= int64(batch.Len())
			p.owned -= min(p.owned, records)
			p.room.Broadcast()
			p.mu.Unlock()
			return batch, nil
		}
		p.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, buf.ErrReadTimeout
		case <-p.ready.Wait():
		}
	}
}

func (p *PacketInbox) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, packet := range p.queued {
		buf.ReleaseMulti(packet)
	}
	p.queued = nil
	p.owned = 0
	p.bytes = 0
	p.ready.Signal()
	p.room.Broadcast()
}
