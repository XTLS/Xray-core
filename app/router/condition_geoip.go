package router

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"

	"go4.org/netipx"
)

type GeoIPMatcher interface {
	// TODO: (PERF) all net.IP -> netipx.Addr
	Match(ip net.IP) bool
	Matches(ips []net.IP) bool
	FilterIPs(ips []net.IP, reverse bool) []net.IP
	Reverse()
	SetReverse(reverse bool)
}

type GeoIPXSet struct {
	ipv4 *netipx.IPSet
	ipv6 *netipx.IPSet
}

type BinarySearchGeoIPMatcher struct {
	set     *GeoIPXSet
	reverse bool
}

// Match implements GeoIPMatcher.
func (m *BinarySearchGeoIPMatcher) Match(ip net.IP) bool {
	ipx, ok := netipx.FromStdIP(ip)
	if !ok {
		return false
	}
	return m.matchAddr(ipx)
}

func (m *BinarySearchGeoIPMatcher) matchAddr(ipx netip.Addr) bool {
	if ipx.Is4() {
		return m.set.ipv4.Contains(ipx) != m.reverse
	}
	if ipx.Is6() {
		return m.set.ipv6.Contains(ipx) != m.reverse
	}
	return false
}

// Matches implements GeoIPMatcher.
func (m *BinarySearchGeoIPMatcher) Matches(ips []net.IP) bool {
	n := len(ips)
	if n == 0 {
		return false
	}

	if n == 1 {
		return m.Match(ips[0])
	}

	buckets := make(map[[7]byte]netip.Addr, n)
	for _, ip := range ips {
		ipx, ok := netipx.FromStdIP(ip)
		if !ok {
			return false
		}
		key, ok := prefixKeyFromIPX(ipx)
		if !ok {
			return false
		}
		buckets[key] = ipx
	}

	for _, ipx := range buckets {
		if !m.matchAddr(ipx) {
			return false
		}
	}
	return true
}

func prefixKeyFromIPX(ipx netip.Addr) (key [7]byte, ok bool) {
	if ipx.Is4() {
		v4 := ipx.As4()
		key[0] = 4
		key[1] = v4[0]
		key[2] = v4[1]
		key[3] = v4[2] // /24
		return key, true
	}
	if ipx.Is6() {
		v6 := ipx.As16()
		key[0] = 6
		key[1] = v6[0]
		key[2] = v6[1]
		key[3] = v6[2]
		key[4] = v6[3]
		key[5] = v6[4]
		key[6] = v6[5] // /48
		return key, true
	}
	return key, false // illegal
}

func prefixKeyFromIP(ip net.IP) (key [7]byte, ok bool) {
	if ip4 := ip.To4(); ip4 != nil {
		key[0] = 4
		key[1] = ip4[0]
		key[2] = ip4[1]
		key[3] = ip4[2] // /24
		return key, true
	}
	if ip16 := ip.To16(); ip16 != nil {
		key[0] = 6
		key[1] = ip16[0]
		key[2] = ip16[1]
		key[3] = ip16[2]
		key[4] = ip16[3]
		key[5] = ip16[4]
		key[6] = ip16[5] // /48
		return key, true
	}
	return key, false // illegal
}

// FilterIPs implements GeoIPMatcher.
func (m *BinarySearchGeoIPMatcher) FilterIPs(ips []net.IP, reverse bool) []net.IP {
	n := len(ips)
	if n == 0 {
		return []net.IP{}
	}

	if n == 1 {
		ip := ips[0]
		if ipx, ok := netipx.FromStdIP(ip); ok {
			if m.matchAddr(ipx) != reverse {
				return ips
			}
		}
		return []net.IP{}
	}

	type bucket struct {
		rep netip.Addr
		ips []net.IP
	}
	buckets := make(map[[7]byte]*bucket, n)
	order := make([][7]byte, 0, n)

	for _, ip := range ips {
		key, ok := prefixKeyFromIP(ip)
		if !ok {
			continue // illegal ip, ignore
		}

		b, exists := buckets[key]
		if !exists {
			// build bucket
			ipx, ok2 := netipx.FromStdIP(ip)
			if !ok2 {
				continue
			}
			b = &bucket{
				rep: ipx,
				ips: make([]net.IP, 0, 4), // for dns answer
			}
			buckets[key] = b
			order = append(order, key)
		}
		b.ips = append(b.ips, ip)
	}

	out := make([]net.IP, 0, n)

	for _, key := range order {
		b := buckets[key]
		matched := m.matchAddr(b.rep)
		if matched != reverse {
			out = append(out, b.ips...)
		}
	}

	return out
}

// Reverse implements GeoIPMatcher.
func (m *BinarySearchGeoIPMatcher) Reverse() {
	m.reverse = !m.reverse
}

// SetReverse implements GeoIPMatcher.
func (m *BinarySearchGeoIPMatcher) SetReverse(reverse bool) {
	m.reverse = reverse
}

type GeneralMultiGeoIPMatcher struct {
	matchers []GeoIPMatcher
}

// Match implements GeoIPMatcher.
func (mm *GeneralMultiGeoIPMatcher) Match(ip net.IP) bool {
	for _, m := range mm.matchers {
		if m.Match(ip) {
			return true
		}
	}
	return false
}

// Matches implements GeoIPMatcher.
func (mm *GeneralMultiGeoIPMatcher) Matches(ips []net.IP) bool {
	for _, m := range mm.matchers {
		if m.Matches(ips) {
			return true
		}
	}
	return false
}

// FilterIPs implements GeoIPMatcher.
func (mm *GeneralMultiGeoIPMatcher) FilterIPs(ips []net.IP, reverse bool) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if _, ok := netipx.FromStdIP(ip); !ok {
			continue // illegal ip, ignore
		}
		matched := false
		for _, m := range mm.matchers {
			if m.Match(ip) {
				matched = true
				break
			}
		}
		if matched != reverse {
			out = append(out, ip)
		}
	}
	return out
}

// Reverse implements GeoIPMatcher.
func (mm *GeneralMultiGeoIPMatcher) Reverse() {
	for _, m := range mm.matchers {
		m.Reverse()
	}
}

// SetReverse implements GeoIPMatcher.
func (mm *GeneralMultiGeoIPMatcher) SetReverse(reverse bool) {
	for _, m := range mm.matchers {
		m.SetReverse(reverse)
	}
}

type BinarySearchMultiGeoIPMatcher struct {
	matchers []*BinarySearchGeoIPMatcher
}

// Match implements GeoIPMatcher.
func (mm *BinarySearchMultiGeoIPMatcher) Match(ip net.IP) bool {
	ipx, ok := netipx.FromStdIP(ip)
	if !ok {
		return false
	}

	for _, m := range mm.matchers {
		if m.matchAddr(ipx) {
			return true
		}
	}
	return false
}

// Matches implements GeoIPMatcher.
func (mm *BinarySearchMultiGeoIPMatcher) Matches(ips []net.IP) bool {
	n := len(ips)
	if n == 0 {
		return false
	}

	if n == 1 {
		return mm.Match(ips[0])
	}

	buckets := make(map[[7]byte]netip.Addr, n)
	for _, ip := range ips {
		ipx, ok := netipx.FromStdIP(ip)
		if !ok {
			return false
		}
		key, ok := prefixKeyFromIPX(ipx)
		if !ok {
			return false
		}
		buckets[key] = ipx
	}

	for _, m := range mm.matchers {
		matched := true
		for _, ipx := range buckets {
			if !m.matchAddr(ipx) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// FilterIPs implements GeoIPMatcher.
func (mm *BinarySearchMultiGeoIPMatcher) FilterIPs(ips []net.IP, reverse bool) []net.IP {
	n := len(ips)
	if n == 0 {
		return []net.IP{}
	}

	if n == 1 {
		ip := ips[0]
		if ipx, ok := netipx.FromStdIP(ip); ok {
			matched := false
			for _, m := range mm.matchers {
				if m.matchAddr(ipx) {
					matched = true
					break
				}
			}
			if matched != reverse {
				return ips
			}
		}
		return []net.IP{}
	}

	type bucket struct {
		rep netip.Addr
		ips []net.IP
	}
	buckets := make(map[[7]byte]*bucket, n)
	order := make([][7]byte, 0, n)

	for _, ip := range ips {
		key, ok := prefixKeyFromIP(ip)
		if !ok {
			continue // illegal ip, ignore
		}

		b, exists := buckets[key]
		if !exists {
			// build bucket
			ipx, ok2 := netipx.FromStdIP(ip)
			if !ok2 {
				continue
			}
			b = &bucket{
				rep: ipx,
				ips: make([]net.IP, 0, 4), // for dns answer
			}
			buckets[key] = b
			order = append(order, key)
		}
		b.ips = append(b.ips, ip)
	}

	out := make([]net.IP, 0, n)

	for _, key := range order {
		b := buckets[key]
		matched := false
		for _, m := range mm.matchers {
			if m.matchAddr(b.rep) {
				matched = true
				break
			}
		}
		if matched != reverse {
			out = append(out, b.ips...)
		}
	}

	return out
}

// Reverse implements GeoIPMatcher.
func (mm *BinarySearchMultiGeoIPMatcher) Reverse() {
	for _, m := range mm.matchers {
		m.Reverse()
	}
}

// SetReverse implements GeoIPMatcher.
func (mm *BinarySearchMultiGeoIPMatcher) SetReverse(reverse bool) {
	for _, m := range mm.matchers {
		m.SetReverse(reverse)
	}
}

type GeoIPXSetFactory struct {
	sync.Mutex
	shared map[string]*GeoIPXSet
}

var geoIPXSetFactory = GeoIPXSetFactory{
	shared: make(map[string]*GeoIPXSet),
}

func (f *GeoIPXSetFactory) GetOrCreate(key string, cidrGroups [][]*CIDR) (*GeoIPXSet, error) {
	f.Lock()
	defer f.Unlock()

	if set := f.shared[key]; set != nil {
		return set, nil
	}

	set, err := f.Create(cidrGroups...)
	if err == nil {
		f.shared[key] = set
	}
	return set, err
}

func (f *GeoIPXSetFactory) Create(cidrGroups ...[]*CIDR) (*GeoIPXSet, error) {
	var ipv4Builder, ipv6Builder netipx.IPSetBuilder

	for _, cidrGroup := range cidrGroups {
		for _, cidrEntry := range cidrGroup {
			ipBytes := cidrEntry.GetIp()
			prefixLen := int(cidrEntry.GetPrefix())

			addr, ok := netip.AddrFromSlice(ipBytes)
			if !ok {
				errors.LogError(context.Background(), "ignore invalid IP byte slice: ", ipBytes)
				continue
			}

			prefix := netip.PrefixFrom(addr, prefixLen)
			if !prefix.IsValid() {
				errors.LogError(context.Background(), "ignore created invalid prefix from addr ", addr, " and length ", prefixLen)
				continue
			}

			if addr.Is4() {
				ipv4Builder.AddPrefix(prefix)
			} else if addr.Is6() {
				ipv6Builder.AddPrefix(prefix)
			}
		}
	}

	ipv4, err := ipv4Builder.IPSet()
	if err != nil {
		return nil, errors.New("failed to build IPv4 set").Base(err)
	}

	ipv6, err := ipv6Builder.IPSet()
	if err != nil {
		return nil, errors.New("failed to build IPv6 set").Base(err)
	}

	return &GeoIPXSet{ipv4: ipv4, ipv6: ipv6}, nil
}

func BuildOptimizedGeoIPMatcher(geoips ...*GeoIP) (GeoIPMatcher, error) {
	n := len(geoips)
	if n == 0 {
		return nil, errors.New("no geoip configs provided")
	}

	var subs []GeoIPMatcher
	pos := make([]*GeoIP, 0, n)
	neg := make([]*GeoIP, 0, n/2)

	for _, geoip := range geoips {
		if geoip == nil {
			return nil, errors.New("geoip entry is nil")
		}
		if geoip.CountryCode == "" {
			set, err := geoIPXSetFactory.Create(geoip.Cidr)
			if err != nil {
				return nil, err
			}
			subs = append(subs, &BinarySearchGeoIPMatcher{set: set, reverse: geoip.ReverseMatch})
			continue
		}
		if !geoip.ReverseMatch {
			pos = append(pos, geoip)
		} else {
			neg = append(neg, geoip)
		}
	}

	tryGetOrCreateMergedIPXSet := func(mergeables []*GeoIP) (*GeoIPXSet, error) {
		n := len(mergeables)
		if n == 0 {
			return nil, nil
		}

		sort.Slice(mergeables, func(i, j int) bool {
			gi, gj := mergeables[i], mergeables[j]
			return gi.CountryCode < gj.CountryCode
		})

		var sb strings.Builder
		sb.Grow(n * 3) // xx,
		cidrGroups := make([][]*CIDR, 0, n)
		var last *GeoIP
		for i, geoip := range mergeables {
			if i == 0 || (geoip.CountryCode != last.CountryCode) {
				last = geoip
				sb.WriteString(geoip.CountryCode)
				sb.WriteString(",")
				cidrGroups = append(cidrGroups, geoip.Cidr)
			}
		}

		return geoIPXSetFactory.GetOrCreate(sb.String(), cidrGroups)
	}

	set, err := tryGetOrCreateMergedIPXSet(pos)
	if err != nil {
		return nil, err
	}
	if set != nil {
		subs = append(subs, &BinarySearchGeoIPMatcher{set: set, reverse: false})
	}

	set, err = tryGetOrCreateMergedIPXSet(neg)
	if err != nil {
		return nil, err
	}
	if set != nil {
		subs = append(subs, &BinarySearchGeoIPMatcher{set: set, reverse: true})
	}

	switch len(subs) {
	case 0:
		return nil, errors.New("no valid geoip matcher")
	case 1:
		return subs[0], nil
	default:
		return &GeneralMultiGeoIPMatcher{matchers: subs}, nil
	}
}
