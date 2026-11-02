package tun

import (
	"slices"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// dnsLeaks is what "dns" in autoSystemWfpBlockLeak stands for: DNS over UDP and
// TCP, Windows' DNS Client service, which may also use other protocols and
// ports, DNS over TLS, and DNS over QUIC.
var dnsLeaks = []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853"}

// ipVersions is a set of IP versions.
type ipVersions uint8

const (
	ipv4Version ipVersions = 1 << iota
	ipv6Version
	bothIPVersions = ipv4Version | ipv6Version
)

// leak is a value of autoSystemWfpBlockLeak: "dns", "windnsclient",
// "misconfigtun", "all", "allexceptlan", "icmp", or "tcp" or "udp", the latter
// two with "/<port>" or "/<low>-<high>" for some ports only, such as "tcp/853"
// or "udp/10-20", and any of them after "ipv4:" or "ipv6:" for one IP version
// only, such as "ipv4:udp/53" or "ipv6:all".
type leak struct {
	versions  ipVersions
	name      string
	low, high uint16 // the ports of "tcp" and "udp", both 0 for all
}

func (l leak) String() string {
	s := l.name
	switch l.versions {
	case ipv4Version:
		s = "ipv4:" + s
	case ipv6Version:
		s = "ipv6:" + s
	}
	switch {
	case l.low == 0:
		return s
	case l.low == l.high:
		return s + "/" + strconv.Itoa(int(l.low))
	default:
		return s + "/" + strconv.Itoa(int(l.low)) + "-" + strconv.Itoa(int(l.high))
	}
}

// covers tells whether l includes connections of protocol to port, over at
// least one IP version.
func (l leak) covers(protocol string, port uint16) bool {
	return l.name == protocol && (l.low == 0 || l.low <= port && port <= l.high)
}

// parseLeak parses a lower case value of autoSystemWfpBlockLeak. Ports go from
// 1 to 65535, low not above high, and "/1-65535" stands for all of them, as
// does no port at all.
func parseLeak(value string) (leak, bool) {
	l := leak{versions: bothIPVersions}
	if version, rest, ok := strings.Cut(value, ":"); ok {
		switch version {
		case "ipv4":
			l.versions = ipv4Version
		case "ipv6":
			l.versions = ipv6Version
		default:
			return leak{}, false
		}
		value = rest
	}
	name, ports, hasPorts := strings.Cut(value, "/")
	l.name = name
	switch name {
	case "tcp", "udp":
	case "dns", "windnsclient", "misconfigtun", "all", "allexceptlan", "icmp":
		return l, !hasPorts
	default:
		return leak{}, false
	}
	if !hasPorts {
		return l, true
	}
	lowText, highText, isRange := strings.Cut(ports, "-")
	low, err := strconv.ParseUint(lowText, 10, 16)
	if err != nil || low == 0 {
		return leak{}, false
	}
	high := low
	if isRange {
		if high, err = strconv.ParseUint(highText, 10, 16); err != nil || high < low {
			return leak{}, false
		}
	}
	if low != 1 || high != 65535 {
		l.low, l.high = uint16(low), uint16(high)
	}
	return l, true
}

// ExpandWfpBlockLeak checks the values of autoSystemWfpBlockLeak and returns
// them in lower case and in order, with "dns" replaced by what it stands for,
// "allexceptlan" followed by that, and ports written the same way, "tcp/1-65535"
// as "tcp" say. Values that only differ in the IP versions become one for
// both: "ipv4:udp/53" and "ipv6:udp/53" turn into "udp/53", as does "udp/53"
// with "ipv4:udp/53".
func ExpandWfpBlockLeak(values []string) ([]string, error) {
	var leaks []leak
	add := func(l leak) {
		for i, added := range leaks {
			if added.versions = l.versions; added == l {
				leaks[i].versions |= l.versions
				return
			}
		}
		leaks = append(leaks, l)
	}
	for _, value := range values {
		l, ok := parseLeak(strings.ToLower(value))
		if !ok {
			return nil, errors.New("unknown autoSystemWfpBlockLeak value: ", value)
		}
		if l.name != "dns" {
			add(l)
		}
		// The local network is no way out for DNS with "allexceptlan", as a
		// resolver there, like the router, would forward outside the TUN.
		if l.name == "dns" || l.name == "allexceptlan" {
			for _, dnsLeak := range dnsLeaks {
				dns, _ := parseLeak(dnsLeak)
				dns.versions = l.versions
				add(dns)
			}
		}
	}
	var expanded []string
	for _, l := range leaks {
		expanded = append(expanded, l.String())
	}
	return expanded, nil
}

// BlocksSystemDNS tells whether expanded autoSystemWfpBlockLeak values keep the
// system's DNS (TCP or UDP port 53, or Windows' DNS Client service) inside the
// TUN, over at least one IP version, which then needs DNS servers of its own.
func BlocksSystemDNS(leaks []string) bool {
	return slices.ContainsFunc(leaks, func(value string) bool {
		l, _ := parseLeak(value)
		return l.name == "windnsclient" || l.name == "all" || l.covers("udp", 53) || l.covers("tcp", 53)
	})
}
