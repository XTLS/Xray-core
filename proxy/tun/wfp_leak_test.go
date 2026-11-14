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
		{[]string{"dns"}, []string{"53", "853", "windnsclient"}, true},
		{[]string{"DNS", "MisconfigTUN"}, []string{"53", "853", "windnsclient", "misconfigtun"}, true},
		{[]string{"tcp/853", "dns", "TCP/0853"}, []string{"tcp/853", "53", "853", "windnsclient"}, true},
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
		{[]string{"AllExceptLAN"}, []string{"allexceptlan", "53", "853", "windnsclient"}, true},
		{[]string{"dns", "allexceptlan", "all"}, []string{"53", "853", "windnsclient", "allexceptlan", "all"}, true},
		// Ports alone, for TCP and UDP.
		{[]string{"53"}, []string{"53"}, true},
		{[]string{"10-20", "0053", "853-853", "53"}, []string{"10-20", "53", "853"}, true},
		{[]string{"54-60", "1-52", "65535"}, []string{"54-60", "1-52", "65535"}, false},
		{[]string{"1-65535"}, []string{"1-65535"}, true},
		{[]string{"853", "tcp/853"}, []string{"853", "tcp/853"}, false},
		// Limited to the addresses of a CIDR.
		{[]string{"1.1.1.0/24:53"}, []string{"1.1.1.0/24:53"}, true},
		{[]string{"1.1.1.1/24:TCP/853", "[2001:DB8::1/32]:udp/10-20", "[::/0]:ICMP"}, []string{"1.1.1.0/24:tcp/853", "[2001:db8::/32]:udp/10-20", "[::/0]:icmp"}, false},
		{[]string{"0.0.0.0/0:dns"}, []string{"0.0.0.0/0:53", "0.0.0.0/0:853", "0.0.0.0/0:windnsclient"}, true},
		{[]string{"[::/0]:all"}, []string{"[::/0]:all"}, true},
		{[]string{"10.0.0.1/32:windnsclient"}, []string{"10.0.0.1/32:windnsclient"}, true},
		{[]string{"[2000::/3]:misconfigtun"}, []string{"[2000::/3]:misconfigtun"}, false},
		{[]string{"1.1.1.0/24:tcp/1-65535", "1.1.1.0/24:udp/53-53"}, []string{"1.1.1.0/24:tcp", "1.1.1.0/24:udp/53"}, true},
		{[]string{"1.1.1.0/24:20-30", "[::/0]:10-10"}, []string{"1.1.1.0/24:20-30", "[::/0]:10"}, false},
		{[]string{"0.0.0.0/0:allexceptlan", "[::/0]:all"}, []string{"0.0.0.0/0:allexceptlan", "0.0.0.0/0:53", "0.0.0.0/0:853", "0.0.0.0/0:windnsclient", "[::/0]:all"}, true},
		{[]string{"1.1.1.1/32:53", "1.1.1.1/32:0053", "1.1.1.1/24:53", "1.1.1.0/24:53", "53"}, []string{"1.1.1.1/32:53", "1.1.1.0/24:53", "53"}, true},
		{[]string{"1.2.3.4/0:icmp", "[::1/0]:icmp", "icmp"}, []string{"0.0.0.0/0:icmp", "[::/0]:icmp", "icmp"}, false},
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
		// Ports alone.
		"0", "00", "65536", "0-10", "20-10", "5-", "-5", "-", "1-2-3", "1-65536", "+53", " 53", "53 ", "53/1", "53/tcp", "0x35",
		// IP versions are CIDRs now.
		"ipv4", "ipv6", "ipv4:udp", "ipv6:all", "ipv4:dns", "tcpv4", "udpv6", "icmpv4", "tcp4", "dnsv4",
		// CIDRs, IPv6 ones in brackets, but neither single addresses nor
		// CIDRs on their own.
		"1.1.1.0/24", "[2001:db8::/32]", "1.1.1.0/24:", "[::/0]:", ":udp", "[]:udp", "[:udp", "[::/0]udp",
		"1.1.1.1:53", "[::1]:53", "[2001:db8::1]:tcp/53", "2001:db8::/32:53", "::/0:all", "[1.1.1.0/24]:53",
		"[2001:db8::]/32:53", "1.1.1.0/33:53", "[::/129]:53", "1.1.1.0/24:1.1.1.0/24:53", "[::/0]:[::/0]:53",
		"1.1.1.0/24 :53", "1.1.1.0/24: 53", " 1.1.1.0/24:53", "1.1.1.0/24::53", "[fe80::%1/64]:53", "geoip:cn:53",
		"1.1.1.0/24:udp/0", "[::/0]:icmp/8", "1.1.1.0/24:dns/53", "[::/0]:20-10", "1.1.1.0/24:ipv4:53", "1.1.1.0/24:geoip",
		"[::ffff:1.1.1.0/120]:53", "[::ffff:0:0/96]:all",
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
		{"53", "udp", 53, true},
		{"53", "tcp", 53, true},
		{"10-20", "tcp", 15, true},
		{"10-20", "udp", 21, false},
		{"1.1.1.0/24:udp/53", "udp", 53, true},
		{"[::/0]:tcp", "tcp", 443, true},
		{"[2001:db8::/32]:53", "tcp", 53, true},
		{"0.0.0.0/0:icmp", "udp", 53, false},
		{"all", "udp", 53, true},
		{"1.1.1.1/32:all", "tcp", 1, true},
		{"allexceptlan", "udp", 53, false},
		{"misconfigtun", "udp", 53, false},
		{"windnsclient", "udp", 53, false},
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
