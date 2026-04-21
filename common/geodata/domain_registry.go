package geodata

import (
	"sync"
	"sync/atomic"
)

type DomainRegistry struct {
	mu       sync.Mutex
	factory  DomainMatcherFactory
	matchers []*DynamicDomainMatcher
}

func (r *DomainRegistry) BuildDomainMatcher(rules []*DomainRule) (DomainMatcher, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m, err := r.factory.BuildMatcher(rules)
	if err != nil {
		return nil, err
	}

	d := NewDynamicDomainMatcher(rules, m)
	r.matchers = append(r.matchers, d)
	return d, nil
}

func (r *DomainRegistry) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	factory := newDomainMatcherFactory()
	type reloadEntry struct {
		dynamic *DynamicDomainMatcher
		matcher DomainMatcher
	}
	reloaded := make([]reloadEntry, len(r.matchers))
	for i, d := range r.matchers {
		m, err := factory.BuildMatcher(d.rules)
		if err != nil {
			return err
		}
		reloaded[i] = reloadEntry{dynamic: d, matcher: m}
	}
	for _, entry := range reloaded {
		entry.dynamic.Reload(entry.matcher)
	}
	r.factory = factory
	return nil
}

func newDomainRegistry() *DomainRegistry {
	return &DomainRegistry{
		factory: newDomainMatcherFactory(),
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
