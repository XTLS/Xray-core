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

// leakPort is a "tcp/<port>" or "udp/<port>" value of autoSystemWfpBlockLeak:
// connections to that port may only go through the TUN.
type leakPort struct {
	tcp  bool
	port uint16
}

func (p leakPort) String() string {
	if p.tcp {
		return "tcp/" + strconv.Itoa(int(p.port))
	}
	return "udp/" + strconv.Itoa(int(p.port))
}

// parseLeakPort parses a lower case "tcp/<port>" or "udp/<port>" value.
func parseLeakPort(value string) (leakPort, bool) {
	protocol, port, ok := strings.Cut(value, "/")
	if !ok || protocol != "tcp" && protocol != "udp" {
		return leakPort{}, false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return leakPort{}, false
	}
	return leakPort{tcp: protocol == "tcp", port: uint16(n)}, true
}

// ExpandWfpBlockLeak checks the values of autoSystemWfpBlockLeak and returns
// them in lower case, in order and without duplicates, with "dns" replaced by
// what it stands for.
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
		case "windnsclient", "misconfigtun":
			add(value)
		default:
			port, ok := parseLeakPort(value)
			if !ok {
				return nil, errors.New("unknown autoSystemWfpBlockLeak value: ", value)
			}
			add(port.String())
		}
	}
	return leaks, nil
}

// BlocksSystemDNS tells whether expanded autoSystemWfpBlockLeak values keep the
// system's DNS (port 53, or Windows' DNS Client service) inside the TUN, which
// then needs DNS servers of its own.
func BlocksSystemDNS(leaks []string) bool {
	return slices.ContainsFunc(leaks, func(leak string) bool {
		return leak == "udp/53" || leak == "tcp/53" || leak == "windnsclient"
	})
}
