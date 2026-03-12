package geodata

type GeoIPRegistry struct {
	ipsetFactory *GeoIPSetFactory
}

func NewGeoIPRegistry() *GeoIPRegistry {
	return &GeoIPRegistry{
		ipsetFactory: &GeoIPSetFactory{shared: make(map[string]*GeoIPSet)},
	}
}

var IPRegistry = NewGeoIPRegistry()
