package tun

import (
	"slices"
	"testing"
)

func TestExpandWfpBlockLeak(t *testing.T) {
	for _, c := range []struct {
		values    []string
		leaks     []string
		systemDNS bool
	}{
		{nil, nil, false},
		{[]string{"dns"}, []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853"}, true},
		{[]string{"DNS", "MisconfigTUN"}, []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853", "misconfigtun"}, true},
		{[]string{"tcp/853", "dns", "TCP/0853"}, []string{"tcp/853", "udp/53", "tcp/53", "windnsclient", "udp/853"}, true},
		{[]string{"tcp/853", "udp/853", "misconfigtun"}, []string{"tcp/853", "udp/853", "misconfigtun"}, false},
		{[]string{"udp/65535", "tcp/1"}, []string{"udp/65535", "tcp/1"}, false},
		{[]string{"tcp/53"}, []string{"tcp/53"}, true},
		{[]string{"windnsclient"}, []string{"windnsclient"}, true},
		{[]string{"ALL"}, []string{"all"}, true},
		{[]string{"tcp", "TCP", "UDP"}, []string{"tcp", "udp"}, true},
		{[]string{"tcp/1-65535", "udp/1-65535"}, []string{"tcp", "udp"}, true},
		{[]string{"udp/10-20", "udp/53-53", "tcp/50-60"}, []string{"udp/10-20", "udp/53", "tcp/50-60"}, true},
		{[]string{"tcp/54-60", "udp/1-52"}, []string{"tcp/54-60", "udp/1-52"}, false},
		{[]string{"ICMP", "icmp"}, []string{"icmp"}, false},
		{[]string{"AllExceptLAN"}, []string{"allexceptlan", "udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853"}, true},
		{[]string{"dns", "allexceptlan", "all"}, []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853", "allexceptlan", "all"}, true},
		// For one IP version only.
		{[]string{"IPv4:TCP/853", "ipv6:udp/10-20", "IPV4:icmp"}, []string{"ipv4:tcp/853", "ipv6:udp/10-20", "ipv4:icmp"}, false},
		{[]string{"ipv4:udp/53"}, []string{"ipv4:udp/53"}, true},
		{[]string{"ipv6:tcp/53-53"}, []string{"ipv6:tcp/53"}, true},
		{[]string{"ipv4:dns"}, []string{"ipv4:udp/53", "ipv4:tcp/53", "ipv4:windnsclient", "ipv4:tcp/853", "ipv4:udp/853"}, true},
		{[]string{"ipv6:all"}, []string{"ipv6:all"}, true},
		{[]string{"ipv4:windnsclient"}, []string{"ipv4:windnsclient"}, true},
		{[]string{"ipv6:misconfigtun"}, []string{"ipv6:misconfigtun"}, false},
		{[]string{"ipv4:allexceptlan", "ipv6:all"}, []string{"ipv4:allexceptlan", "ipv4:udp/53", "ipv4:tcp/53", "ipv4:windnsclient", "ipv4:tcp/853", "ipv4:udp/853", "ipv6:all"}, true},
		// Values that only differ in the IP versions become one.
		{[]string{"ipv4:udp/53", "tcp", "ipv6:udp/53"}, []string{"udp/53", "tcp"}, true},
		{[]string{"ipv6:tcp/1-65535", "ipv4:tcp"}, []string{"tcp"}, true},
		{[]string{"ipv4:icmp", "icmp"}, []string{"icmp"}, false},
		{[]string{"ipv4:tcp/853", "ipv6:tcp/853-853", "ipv6:tcp/854"}, []string{"tcp/853", "ipv6:tcp/854"}, false},
		{[]string{"dns", "ipv4:dns"}, []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853"}, true},
		{[]string{"ipv4:dns", "ipv6:udp/53"}, []string{"udp/53", "ipv4:tcp/53", "ipv4:windnsclient", "ipv4:tcp/853", "ipv4:udp/853"}, true},
		{[]string{"ipv4:misconfigtun", "ipv6:misconfigtun", "ipv6:all", "ipv4:all"}, []string{"misconfigtun", "all"}, true},
	} {
		leaks, err := ExpandWfpBlockLeak(c.values)
		if err != nil {
			t.Errorf("%v: %v", c.values, err)
			continue
		}
		if !slices.Equal(leaks, c.leaks) {
			t.Errorf("%v: got %v, want %v", c.values, leaks, c.leaks)
		}
		if got := BlocksSystemDNS(leaks); got != c.systemDNS {
			t.Errorf("%v: BlocksSystemDNS() = %v", c.values, got)
		}
	}
	for _, value := range []string{
		"", "ip", "tcp/", "udp/65536", "tcp/-1", "tcp/+53", "tcp/53/1", "udp/abc", "icmp/0", "icmp/8", "tcp:53", " dns",
		"tcp/0-10", "tcp/20-10", "tcp/5-", "tcp/-5", "tcp/1-2-3", "tcp/1-65536", "udp/ 53", "all/0", "dns/53", "windnsclient/53",
		"tcp/0", "udp/0", "tcp/00", "udp/0-0", "udp/65535-1",
		"ipv4", "ipv6", "ipv4:", ":udp", "ipv5:udp", "ip:all", "v4:udp", "ipv4/udp", "ipv4 :udp", "ipv4: udp", "ipv4:ipv6:udp",
		"ipv4:ipv4", "ipv4:tcp/0", "ipv6:icmp/8", "ipv4:dns/53", "ipv6:udp/20-10", "ipv4+ipv6:udp",
		"tcpv4", "udpv6", "icmpv4", "tcpv4/853", "tcp4", "udp6", "dnsv4", "allv6",
	} {
		if _, err := ExpandWfpBlockLeak([]string{value}); err == nil {
			t.Errorf("%q was accepted", value)
		}
	}
}

func TestLeakCovers(t *testing.T) {
	for _, c := range []struct {
		value    string
		protocol string
		port     uint16
		covers   bool
	}{
		{"tcp", "tcp", 1, true},
		{"tcp", "udp", 53, false},
		{"udp/53", "udp", 53, true},
		{"udp/53", "udp", 54, false},
		{"tcp/10-20", "tcp", 10, true},
		{"tcp/10-20", "tcp", 20, true},
		{"tcp/10-20", "tcp", 21, false},
		{"tcp/10-20", "tcp", 9, false},
		{"ipv4:udp/53", "udp", 53, true},
		{"ipv6:tcp", "tcp", 443, true},
		{"ipv4:icmp", "udp", 53, false},
		{"all", "udp", 53, false},
	} {
		l, ok := parseLeak(c.value)
		if !ok {
			t.Errorf("%q was not parsed", c.value)
			continue
		}
		if got := l.covers(c.protocol, c.port); got != c.covers {
			t.Errorf("%q covers %s/%d = %v", c.value, c.protocol, c.port, got)
		}
	}
}
