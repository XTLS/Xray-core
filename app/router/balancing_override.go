package router

import (
	sync "sync"
	"time"

	"github.com/xtls/xray-core/features/outbound"
)

func (b *Balancer) overrideSelecting(selects []string, validity time.Duration) error {
	if validity <= 0 {
		b.override.Clear()
		return nil
	}
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return newError("outbound.Manager is not a HandlerSelector")
	}
	tags := hs.Select(selects)
	if len(tags) == 0 {
		return newError("no outbound selected")
	}
	b.override.Put(tags, time.Now().Add(validity))
	return nil
}

// OverrideSelecting implements routing.BalancingOverrider
func (r *Router) OverrideSelecting(balancer string, selects []string, validity time.Duration) error {
	var b *Balancer
	for tag, bl := range r.balancers {
		if tag == balancer {
			b = bl
			break
		}
	}
	if b == nil {
		return newError("balancer '", balancer, "' not found")
	}
	err := b.overrideSelecting(selects, validity)
	if err != nil {
		return err
	}
	return nil
}

type overriddenSettings struct {
	selects []string
	until   time.Time
}

type overridden struct {
	access   sync.RWMutex
	settings overriddenSettings
}

// Get gets the overridden settings
func (o *overridden) Get() *overriddenSettings {
	o.access.RLock()
	defer o.access.RUnlock()
	if len(o.settings.selects) == 0 || time.Now().After(o.settings.until) {
		return nil
	}
	return &overriddenSettings{
		selects: o.settings.selects,
		until:   o.settings.until,
	}
}

// Put updates the overridden settings
func (o *overridden) Put(selects []string, until time.Time) {
	o.access.Lock()
	defer o.access.Unlock()
	o.settings.selects = selects
	o.settings.until = until
}

// Clear clears the overridden settings
func (o *overridden) Clear() {
	o.access.Lock()
	defer o.access.Unlock()
	o.settings.selects = nil
	o.settings.until = time.Time{}
}
