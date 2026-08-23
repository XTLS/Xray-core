package router

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

func (r *Router) OverrideBalancer(balancer string, target string) error {
	b, ok := r.getBalancer(balancer)
	if !ok {
		return errors.New("balancer '", balancer, "' not found")
	}

	b.override.Put(target)
	return nil
}

type overrideSettings struct {
	target string
}

type override struct {
	access   sync.RWMutex
	settings overrideSettings
}

// Get gets the override settings
func (o *override) Get() string {
	o.access.RLock()
	defer o.access.RUnlock()
	return o.settings.target
}

// Put updates the override settings
func (o *override) Put(target string) {
	o.access.Lock()
	defer o.access.Unlock()
	o.settings.target = target
}

// Clear clears the override settings
func (o *override) Clear() {
	o.access.Lock()
	defer o.access.Unlock()
	o.settings.target = ""
}
