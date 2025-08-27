package router

import (
	"net/netip"
	"strconv"

	"github.com/xtls/xray-core/common/net"
	"go4.org/netipx"
)

type GeoIPMatcher struct {
	countryCode  string
	reverseMatch bool
	ip4          *netipx.IPSet
	ip6          *netipx.IPSet
}

func (m *GeoIPMatcher) Init(cidrs []*CIDR) error {
	var builder4, builder6 netipx.IPSetBuilder

	for _, cidr := range cidrs {
		ip := net.IP(cidr.GetIp())
		ipPrefixString := ip.String() + "/" + strconv.Itoa(int(cidr.GetPrefix()))
		ipPrefix, err := netip.ParsePrefix(ipPrefixString)
		if err != nil {
			return err
		}

		switch len(ip) {
		case net.IPv4len:
			builder4.AddPrefix(ipPrefix)
		case net.IPv6len:
			builder6.AddPrefix(ipPrefix)
		}
	}

	if ip4, err := builder4.IPSet(); err != nil {
		return err
	} else {
		m.ip4 = ip4
	}

	if ip6, err := builder6.IPSet(); err != nil {
		return err
	} else {
		m.ip6 = ip6
	}

	return nil
}

func (m *GeoIPMatcher) SetReverseMatch(isReverseMatch bool) {
	m.reverseMatch = isReverseMatch
}

func (m *GeoIPMatcher) match4(ip net.IP) bool {
	nip, ok := netipx.FromStdIP(ip)
	if !ok {
		return false
	}

	return m.ip4.Contains(nip)
}

func (m *GeoIPMatcher) match6(ip net.IP) bool {
	nip, ok := netipx.FromStdIP(ip)
	if !ok {
		return false
	}

	return m.ip6.Contains(nip)
}

// Match returns true if the given ip is included by the GeoIP.
func (m *GeoIPMatcher) Match(ip net.IP) bool {
	isMatched := false
	switch len(ip) {
	case net.IPv4len:
		isMatched = m.match4(ip)
	case net.IPv6len:
		isMatched = m.match6(ip)
	}
	if m.reverseMatch {
		return !isMatched
	}
	return isMatched
}

// GeoIPMatcherContainer is a container for GeoIPMatchers. It keeps unique copies of GeoIPMatcher by country code.
type GeoIPMatcherContainer struct {
	matchers []*GeoIPMatcher
}

// Add adds a new GeoIP set into the container.
// If the country code of GeoIP is not empty, GeoIPMatcherContainer will try to find an existing one, instead of adding a new one.
func (c *GeoIPMatcherContainer) Add(geoip *GeoIP) (*GeoIPMatcher, error) {
	if len(geoip.CountryCode) > 0 {
		for _, m := range c.matchers {
			if m.countryCode == geoip.CountryCode && m.reverseMatch == geoip.ReverseMatch {
				return m, nil
			}
		}
	}

	m := &GeoIPMatcher{
		countryCode:  geoip.CountryCode,
		reverseMatch: geoip.ReverseMatch,
	}
	if err := m.Init(geoip.Cidr); err != nil {
		return nil, err
	}
	if len(geoip.CountryCode) > 0 {
		c.matchers = append(c.matchers, m)
	}
	return m, nil
}

var GlobalGeoIPContainer GeoIPMatcherContainer

func MatchIPs(matchers []*GeoIPMatcher, ips []net.IP, reverse bool) []net.IP {
	if len(matchers) == 0 {
		panic("GeoIP matchers should not be empty to avoid ambiguity")
	}
	newIPs := make([]net.IP, 0, len(ips))
	var isFound bool
	for _, ip := range ips {
		isFound = false
		for _, matcher := range matchers {
			if matcher.Match(ip) {
				isFound = true
				break
			}
		}
		if isFound && !reverse {
			newIPs = append(newIPs, ip)
			continue
		}
		if !isFound && reverse {
			newIPs = append(newIPs, ip)
			continue
		}
	}
	return newIPs
}
