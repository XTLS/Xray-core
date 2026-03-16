package geodata

type GeoIPRegistry struct {
	ipsetFactory *GeoIPSetFactory
}

func (r *GeoIPRegistry) BuildGeoIPMatcher(rules []*IPRule) (GeoIPMatcher, error) {
	return buildOptimizedGeoIPMatcher(r.ipsetFactory, rules)
}

func newGeoIPRegistry() *GeoIPRegistry {
	return &GeoIPRegistry{
		ipsetFactory: &GeoIPSetFactory{shared: make(map[string]*GeoIPSet)},
	}
}

var IPRegistry = newGeoIPRegistry()
