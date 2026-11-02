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

// leakTraffic is a "tcp", "udp" or "icmp" value of autoSystemWfpBlockLeak, the
// former two with "/<port>" or "/<low>-<high>" for some ports only, such as
// "tcp/853" or "udp/10-20": connections of that protocol, to those ports, may
// only go through the TUN.
type leakTraffic struct {
	protocol  string // "tcp", "udp" or "icmp"
	low, high uint16 // the ports, both 0 for all
}

func (t leakTraffic) String() string {
	switch {
	case t.low == 0:
		return t.protocol
	case t.low == t.high:
		return t.protocol + "/" + strconv.Itoa(int(t.low))
	default:
		return t.protocol + "/" + strconv.Itoa(int(t.low)) + "-" + strconv.Itoa(int(t.high))
	}
}

// covers tells whether t includes connections of protocol to port.
func (t leakTraffic) covers(protocol string, port uint16) bool {
	return t.protocol == protocol && (t.low == 0 || t.low <= port && port <= t.high)
}

// parseLeakTraffic parses a lower case "tcp", "udp" or "icmp" value. The former
// two may end in "/<port>" or "/<low>-<high>", with ports from 1 to 65535 and
// low not above high, where "/1-65535" stands for all ports, as does no port
// at all; ICMP has no ports.
func parseLeakTraffic(value string) (leakTraffic, bool) {
	protocol, ports, hasPorts := strings.Cut(value, "/")
	switch protocol {
	case "tcp", "udp":
	case "icmp":
		return leakTraffic{protocol: protocol}, !hasPorts
	default:
		return leakTraffic{}, false
	}
	if !hasPorts {
		return leakTraffic{protocol: protocol}, true
	}
	lowText, highText, isRange := strings.Cut(ports, "-")
	low, err := strconv.ParseUint(lowText, 10, 16)
	if err != nil || low == 0 {
		return leakTraffic{}, false
	}
	high := low
	if isRange {
		if high, err = strconv.ParseUint(highText, 10, 16); err != nil || high < low {
			return leakTraffic{}, false
		}
	}
	if low == 1 && high == 65535 {
		return leakTraffic{protocol: protocol}, true
	}
	return leakTraffic{protocol: protocol, low: uint16(low), high: uint16(high)}, true
}

// ExpandWfpBlockLeak checks the values of autoSystemWfpBlockLeak and returns
// them in lower case, in order and without duplicates, with "dns" replaced by
// what it stands for, "allexceptlan" followed by that, and ports written the
// same way, "tcp/1-65535" as "tcp" say.
func ExpandWfpBlockLeak(values []string) ([]string, error) {
	var leaks []string
	add := func(leak string) {
		if !slices.Contains(leaks, leak) {
			leaks = append(leaks, leak)
		}
	}
	for _, value := range values {
		switch value = strings.ToLower(value); value {
		case "dns":
			for _, leak := range dnsLeaks {
				add(leak)
			}
		case "windnsclient", "misconfigtun", "all":
			add(value)
		case "allexceptlan":
			// The local network is no way out for DNS, which a resolver
			// there, like the router, would forward outside the TUN.
			add(value)
			for _, leak := range dnsLeaks {
				add(leak)
			}
		default:
			traffic, ok := parseLeakTraffic(value)
			if !ok {
				return nil, errors.New("unknown autoSystemWfpBlockLeak value: ", value)
			}
			add(traffic.String())
		}
	}
	return leaks, nil
}

// BlocksSystemDNS tells whether expanded autoSystemWfpBlockLeak values keep the
// system's DNS (TCP or UDP port 53, or Windows' DNS Client service) inside the
// TUN, which then needs DNS servers of its own.
func BlocksSystemDNS(leaks []string) bool {
	return slices.ContainsFunc(leaks, func(leak string) bool {
		if leak == "windnsclient" || leak == "all" {
			return true
		}
		traffic, ok := parseLeakTraffic(leak)
		return ok && (traffic.covers("udp", 53) || traffic.covers("tcp", 53))
	})
}
