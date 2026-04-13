package geodata

type DomainRegistry struct {
	factory DomainMatcherFactory
}

func (r *DomainRegistry) BuildDomainMatcher(rules []*DomainRule) (DomainMatcher, error) {
	return r.factory.BuildMatcher(rules)
}

func newDomainRegistry() *DomainRegistry {
	return &DomainRegistry{
		factory: newDomainMatcherFactory(),
	}
}

var DomainReg = newDomainRegistry()
