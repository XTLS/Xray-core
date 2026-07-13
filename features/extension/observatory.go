package extension

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/features"
	"google.golang.org/protobuf/proto"
)

// ErrObservatoryProbeNetworkUnavailable reports that a one-shot batch could
// not distinguish outbound health because the underlying network was down.
// Implementations must not publish an all-failed replacement snapshot for
// this condition.
var ErrObservatoryProbeNetworkUnavailable = errors.New("underlying network is unavailable during observatory probe")

type Observatory interface {
	features.Feature

	GetObservation(ctx context.Context) (proto.Message, error)
}

type BurstObservatory interface {
	Observatory
	Check(tag []string)
}

// ObservatoryBatchProbe runs a finite set of outbound probes through one
// already-created Xray instance. It is intended for embedders that need to
// compare many outbounds without creating one core instance per outbound.
// Implementations must honor ctx cancellation and must not exceed
// maxConcurrency probes in flight. After a successful return, GetObservation
// must expose the completed batch as one result snapshot.
type ObservatoryBatchProbe interface {
	Observatory
	// ProbeOutboundsDeadline returns the configured worst-case probe time
	// budget for the requested batch. Callers may add platform-specific
	// scheduling and cleanup grace when constructing an external deadline.
	ProbeOutboundsDeadline(tags []string, maxConcurrency, samples int) (time.Duration, error)
	ProbeOutbounds(ctx context.Context, tags []string, maxConcurrency, samples int) error
}

// ObservatoryUpdateNotifier publishes an event after an observatory result
// changes. Consumers should query GetObservation or their routing strategy in
// the callback instead of treating the event itself as a routing decision.
type ObservatoryUpdateNotifier interface {
	SubscribeObservationUpdates(listener func()) (unsubscribe func())
}

// ObservatoryProbeDeadline reports the longest expected time before a
// scheduled observer's initial probe cycle can publish an observation. Batch
// callers must use ObservatoryBatchProbe.ProbeOutboundsDeadline instead.
type ObservatoryProbeDeadline interface {
	ObservationProbeDeadline() time.Duration
}

// ObservatoryUpdateDispatcher provides instance-scoped update subscriptions
// shared by observatory implementations.
type ObservatoryUpdateDispatcher struct {
	access    sync.RWMutex
	nextID    uint64
	listeners map[uint64]func()
}

func (d *ObservatoryUpdateDispatcher) SubscribeObservationUpdates(listener func()) func() {
	if listener == nil {
		return func() {}
	}
	d.access.Lock()
	if d.listeners == nil {
		d.listeners = make(map[uint64]func())
	}
	id := d.nextID
	d.nextID++
	d.listeners[id] = listener
	d.access.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			d.access.Lock()
			delete(d.listeners, id)
			d.access.Unlock()
		})
	}
}

func (d *ObservatoryUpdateDispatcher) NotifyObservationUpdate() {
	d.access.RLock()
	listeners := make([]func(), 0, len(d.listeners))
	for _, listener := range d.listeners {
		listeners = append(listeners, listener)
	}
	d.access.RUnlock()

	for _, listener := range listeners {
		listener()
	}
}

func ObservatoryType() interface{} {
	return (*Observatory)(nil)
}
