package geodata

type DomainRegistry struct{}

func (r *DomainRegistry) BuildDomainMatcher(rules []*DomainRule) (DomainMatcher, error) {
	return buildDomainMatcher(rules)
}

func newDomainRegistry() *DomainRegistry {
	return &DomainRegistry{}
}

var DomainReg = newDomainRegistry()
