package tun

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// dnsLeaks is what "dns" in autoSystemWfpBlockLeak stands for: DNS over TCP
// and UDP, DNS over TLS and QUIC, and Windows' DNS Client service, which may
// also use other protocols and ports.
var dnsLeaks = []string{"53", "853", "windnsclient"}

// leak is a value of autoSystemWfpBlockLeak: "dns", "windnsclient",
// "misconfigtun", "all", "allexceptlan", "icmp", or "tcp" or "udp", the latter
// two with "/<port>" or "/<low>-<high>" for some ports only, such as "tcp/853"
// or "udp/10-20", or such ports alone for TCP and UDP, such as "53". A CIDR in
// front limits any of them to its addresses, an IPv6 one in brackets, such as
// "1.1.1.0/24:53" or "[::/0]:all".
type leak struct {
	prefix    netip.Prefix // all addresses of both IP versions if not valid
	name      string       // empty for TCP and UDP to some ports
	low, high uint16       // the ports of TCP and UDP, both 0 for all
}

func (l leak) String() string {
	s := l.name
	if l.low != 0 {
		if s != "" {
			s += "/"
		}
		s += strconv.Itoa(int(l.low))
		if l.high != l.low {
			s += "-" + strconv.Itoa(int(l.high))
		}
	}
	switch {
	case !l.prefix.IsValid():
		return s
	case l.prefix.Addr().Is6():
		return "[" + l.prefix.String() + "]:" + s
	default:
		return l.prefix.String() + ":" + s
	}
}

// covers tells whether l includes connections of protocol, "tcp" or "udp", to
// port, to at least some addresses.
func (l leak) covers(protocol string, port uint16) bool {
	switch l.name {
	case "all":
		return true
	case "", protocol:
		return l.low == 0 || l.low <= port && port <= l.high
	}
	return false
}

// blocksDNS tells whether l keeps the system's DNS, TCP or UDP port 53 or
// Windows' DNS Client service, inside the TUN, to at least some addresses.
func (l leak) blocksDNS() bool {
	return l.name == "windnsclient" || l.covers("udp", 53) || l.covers("tcp", 53)
}

// parseLeak parses a lower case value of autoSystemWfpBlockLeak. Ports go from
// 1 to 65535, low not above high, and "tcp/1-65535" stands for all of them, as
// does "tcp".
func parseLeak(value string) (leak, bool) {
	var l leak
	cidr, rest, hasCIDR := strings.Cut(value, ":")
	ipv6 := strings.HasPrefix(value, "[")
	if ipv6 {
		cidr, rest, hasCIDR = strings.Cut(value[1:], "]:")
	}
	if hasCIDR {
		// IPv4-mapped IPv6 ones would not match: Windows checks such
		// connections as IPv4.
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Addr().Is6() != ipv6 || prefix.Addr().Is4In6() {
			return leak{}, false
		}
		l.prefix, value = prefix.Masked(), rest
	}
	name, ports, hasPorts := strings.Cut(value, "/")
	switch name {
	case "tcp", "udp":
		l.name = name
		if !hasPorts {
			return l, true
		}
	case "dns", "windnsclient", "misconfigtun", "all", "allexceptlan", "icmp":
		l.name = name
		return l, !hasPorts
	default:
		if hasPorts {
			return leak{}, false
		}
		ports = name // for TCP and UDP
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
	if l.name == "" || low != 1 || high != 65535 {
		l.low, l.high = uint16(low), uint16(high)
	}
	return l, true
}

// ExpandWfpBlockLeak checks the values of autoSystemWfpBlockLeak and returns
// them in lower case, in order and each once, with "dns" replaced by what it
// stands for, "allexceptlan" followed by that, CIDRs masked, and ports written
// the same way, "tcp/1-65535" as "tcp" say.
func ExpandWfpBlockLeak(values []string) ([]string, error) {
	var expanded []string
	add := func(l leak) {
		if value := l.String(); !slices.Contains(expanded, value) {
			expanded = append(expanded, value)
		}
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
				dns.prefix = l.prefix
				add(dns)
			}
		}
	}
	return expanded, nil
}

// BlocksSystemDNS tells whether expanded autoSystemWfpBlockLeak values keep the
// system's DNS (TCP or UDP port 53, or Windows' DNS Client service) inside the
// TUN, to at least some addresses, which then needs DNS servers of its own.
func BlocksSystemDNS(leaks []string) bool {
	return slices.ContainsFunc(leaks, func(value string) bool {
		l, _ := parseLeak(value)
		return l.blocksDNS()
	})
}
