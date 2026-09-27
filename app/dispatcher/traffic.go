package dispatcher

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/pipe"
)

type accessTrafficKeyType struct{}

var accessTrafficKey accessTrafficKeyType

// counterFanout is a stats.Counter that adds to all its counters at once, so
// that a single SizeStatWriter or TimeoutWrapperReader can feed user stats and
// access log traffic at the same time. It also forwards Hold to the
// per-connection traffic counter, the only Holdable counter of a fanout.
type counterFanout []stats.Counter

// Add implements stats.Counter.
func (f counterFanout) Add(delta int64) int64 {
	for _, c := range f {
		c.Add(delta)
	}
	return 0
}

// Value implements stats.Counter.
func (f counterFanout) Value() int64 {
	if len(f) == 0 {
		return 0
	}
	return f[0].Value()
}

// Set implements stats.Counter.
func (f counterFanout) Set(value int64) int64 {
	for _, c := range f {
		c.Set(value)
	}
	return 0
}

// Hold implements stats.Holdable.
func (f counterFanout) Hold() func() {
	for _, c := range f {
		if h, ok := c.(stats.Holdable); ok {
			return h.Hold()
		}
	}
	return func() {}
}

// fanoutCounter combines the non-nil counters into a single stats.Counter.
func fanoutCounter(counters ...stats.Counter) stats.Counter {
	var f counterFanout
	for _, c := range counters {
		if c != nil {
			f = append(f, c)
		}
	}
	return f
}

// directionTraffic counts the bytes flowing in one direction of a dispatched
// connection. Transfers that account their size only when they finish, like
// raw copies or the reads of a TimeoutWrapperReader, bracket themselves with
// Hold while running, so that a settled direction can be waited on for a
// complete count.
type directionTraffic struct {
	value   int64
	mu      sync.RWMutex // serializes counting with settling
	settled bool         // the direction settled, under mu
	pending sync.WaitGroup
}

// Value implements stats.Counter.
func (d *directionTraffic) Value() int64 {
	return atomic.LoadInt64(&d.value)
}

// Set implements stats.Counter.
func (d *directionTraffic) Set(value int64) int64 {
	return atomic.SwapInt64(&d.value, value)
}

// Add implements stats.Counter.
func (d *directionTraffic) Add(delta int64) int64 {
	// Counting runs under the read lock, so that settling (which takes the
	// write lock) cannot cut in between a started accounting operation and
	// the snapshot.
	d.mu.RLock()
	defer d.mu.RUnlock()
	return atomic.AddInt64(&d.value, delta)
}

// Hold implements stats.Holdable. Transfers that start after the direction
// settled are not waited for: every transfer of a connection brackets itself
// before it can possibly outlive the connection (buf.Copy holds its
// endpoints for its whole duration).
func (d *directionTraffic) Hold() func() {
	d.mu.Lock()
	if d.settled {
		d.mu.Unlock()
		return func() {}
	}
	d.pending.Add(1)
	d.mu.Unlock()
	return d.pending.Done
}

// finish settles the direction and waits for the transfers that started
// before that, so that their accounting completes before the value is read.
// It must not run on the connection's own call stack, e.g. DispatchLink:
// such transfers may only finish after the connection's caller returned.
func (d *directionTraffic) finish() {
	d.mu.Lock()
	d.settled = true
	d.mu.Unlock()
	d.pending.Wait()
}

// accessTraffic accumulates the uplink and downlink byte counts of one
// dispatched connection, and records the access log message once the
// connection ends.
//
// Each direction settles when no more data can flow through it. For links
// created by the dispatcher (Dispatch) this is the moment the underlying pipe
// is closed or interrupted; for caller-provided links (DispatchLink), which
// contain no pipe of their own, it is the return of the outbound handler.
type accessTraffic struct {
	uplink   *directionTraffic
	downlink *directionTraffic

	// upDone and downDone are closed when the direction is finished.
	upDone   <-chan struct{}
	downDone <-chan struct{}

	// Settle channels owned by this instance, nil when the done signals come
	// from pipes.
	upClose, downClose chan struct{}
	upOnce, downOnce   sync.Once
}

// newPipeAccessTraffic creates an accessTraffic that settles together with the
// uplink and downlink pipes of a link created by the dispatcher.
func newPipeAccessTraffic(uplink, downlink *pipe.Reader) *accessTraffic {
	return &accessTraffic{
		uplink:   new(directionTraffic),
		downlink: new(directionTraffic),
		upDone:   uplink.WaitClosed(),
		downDone: downlink.WaitClosed(),
	}
}

// newLinkAccessTraffic creates an accessTraffic for a caller-provided link. It
// settles when settle is called, after the outbound handler has returned.
func newLinkAccessTraffic() *accessTraffic {
	upClose := make(chan struct{})
	downClose := make(chan struct{})
	return &accessTraffic{
		uplink:    new(directionTraffic),
		downlink:  new(directionTraffic),
		upDone:    upClose,
		downDone:  downClose,
		upClose:   upClose,
		downClose: downClose,
	}
}

// settle marks both directions of the connection as finished, without waiting
// for transfers that are still running: they may only complete after the
// caller of DispatchLink returned. It is safe to call multiple times, and
// does nothing for pipe-based trackers.
func (t *accessTraffic) settle() {
	if t.upClose != nil {
		t.upOnce.Do(func() { close(t.upClose) })
	}
	if t.downClose != nil {
		t.downOnce.Do(func() { close(t.downClose) })
	}
}

// deferredRecord arms the tracker: once both directions settled and the
// transfers that already started finished their accounting, the message is
// recorded a single time, together with the accumulated byte counts. The
// message is copied right away, so that later changes to it cannot alter the
// record; only the byte counts are filled in when recording.
func (t *accessTraffic) deferredRecord(message *log.AccessMessage) {
	m := *message
	go func() {
		<-t.upDone
		t.uplink.finish()
		<-t.downDone
		t.downlink.finish()
		m.Uplink = t.uplink.Value()
		m.Downlink = t.downlink.Value()
		log.Record(&m)
	}()
}

func contextWithAccessTraffic(ctx context.Context, t *accessTraffic) context.Context {
	if t == nil && accessTrafficFromContext(ctx) == nil {
		return ctx
	}
	return context.WithValue(ctx, accessTrafficKey, t)
}

func accessTrafficFromContext(ctx context.Context) *accessTraffic {
	if t, ok := ctx.Value(accessTrafficKey).(*accessTraffic); ok {
		return t
	}
	return nil
}
