package geodata

type IPRegistry struct {
	ipsetFactory *IPSetFactory
}

func (r *IPRegistry) BuildIPMatcher(rules []*IPRule) (IPMatcher, error) {
	return buildOptimizedIPMatcher(r.ipsetFactory, rules)
}

func newIPRegistry() *IPRegistry {
	return &IPRegistry{
		ipsetFactory: &IPSetFactory{shared: make(map[string]*IPSet)},
	}
}

var IPReg = newIPRegistry()
