package geodata

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/common/uuid"
)

type DomainRegistry struct {
	mu       sync.Mutex
	factory  DomainMatcherFactory
	matchers *utils.WeakCacheMap[uuid.UUID, DynamicDomainMatcher]
}

func (r *DomainRegistry) BuildDomainMatcher(rules []*DomainRule) (DomainMatcher, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m, err := r.factory.BuildMatcher(rules)
	if err != nil {
		return nil, err
	}

	d := NewDynamicDomainMatcher(rules, m)
	r.matchers.Store(uuid.New(), d)
	return d, nil
}

func (r *DomainRegistry) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var matchers []*DynamicDomainMatcher
	r.matchers.Range(func(_ uuid.UUID, matcher *DynamicDomainMatcher) bool {
		matchers = append(matchers, matcher)
		return true
	})
	errors.LogInfo(context.Background(), "reloading GeoSite data for ", len(matchers), " domain matcher(s)")

	factory := newDomainMatcherFactory()
	type reloadEntry struct {
		dynamic *DynamicDomainMatcher
		matcher DomainMatcher
	}
	reloaded := make([]reloadEntry, len(matchers))
	for i, d := range matchers {
		m, err := factory.BuildMatcher(d.rules)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to reload GeoSite data for domain matcher ", i)
			return err
		}
		reloaded[i] = reloadEntry{dynamic: d, matcher: m}
	}
	for _, entry := range reloaded {
		entry.dynamic.Reload(entry.matcher)
	}
	r.factory = factory
	errors.LogInfo(context.Background(), "reloaded GeoSite data for ", len(matchers), " domain matcher(s)")
	return nil
}

func newDomainRegistry() *DomainRegistry {
	return &DomainRegistry{
		factory:  newDomainMatcherFactory(),
		matchers: utils.NewWeakCacheMap[uuid.UUID, DynamicDomainMatcher](),
	}
}

var DomainReg = newDomainRegistry()

type domainMatcherState struct {
	matcher DomainMatcher
}

type DynamicDomainMatcher struct {
	rules []*DomainRule
	state atomic.Pointer[domainMatcherState]
}

// Match implements DomainMatcher.
func (d *DynamicDomainMatcher) Match(input string) []uint32 {
	return d.state.Load().matcher.Match(input)
}

// MatchAny implements DomainMatcher.
func (d *DynamicDomainMatcher) MatchAny(input string) bool {
	return d.state.Load().matcher.MatchAny(input)
}

func (d *DynamicDomainMatcher) Reload(newMatcher DomainMatcher) {
	d.state.Store(&domainMatcherState{matcher: newMatcher})
}

func NewDynamicDomainMatcher(rules []*DomainRule, matcher DomainMatcher) *DynamicDomainMatcher {
	d := &DynamicDomainMatcher{rules: rules}
	d.Reload(matcher)
	return d
}
