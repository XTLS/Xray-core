package extension

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/features"
	"google.golang.org/protobuf/proto"
)

type Observatory interface {
	features.Feature

	GetObservation(ctx context.Context) (proto.Message, error)
}

type BurstObservatory interface {
	Observatory
	Check(tag []string)
}

// ObservatoryUpdateNotifier publishes an event after an observatory result
// changes. Consumers should query GetObservation or their routing strategy in
// the callback instead of treating the event itself as a routing decision.
type ObservatoryUpdateNotifier interface {
	SubscribeObservationUpdates(listener func()) (unsubscribe func())
}

// ObservatoryProbeDeadline reports the longest expected time before the
// initial probe cycle can publish an observation. Callers may use it to bound
// temporary routing state without expiring that state before the observatory
// has had a chance to produce a result.
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
