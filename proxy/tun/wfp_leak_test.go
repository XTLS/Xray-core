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
		{[]string{"tcp", "TCP/0", "udp/0", "UDP"}, []string{"tcp", "udp"}, true},
		{[]string{"tcp/1-65535", "udp/1-65535"}, []string{"tcp", "udp"}, true},
		{[]string{"udp/10-20", "udp/53-53", "tcp/50-60"}, []string{"udp/10-20", "udp/53", "tcp/50-60"}, true},
		{[]string{"tcp/54-60", "udp/1-52"}, []string{"tcp/54-60", "udp/1-52"}, false},
		{[]string{"ICMP", "icmp"}, []string{"icmp"}, false},
		{[]string{"AllExceptLAN"}, []string{"allexceptlan", "udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853"}, true},
		{[]string{"dns", "allexceptlan", "all"}, []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853", "allexceptlan", "all"}, true},
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
		"tcp/0-10", "tcp/20-10", "tcp/5-", "tcp/-5", "tcp/1-2-3", "tcp/1-65536", "udp/ 53", "all/0",
	} {
		if _, err := ExpandWfpBlockLeak([]string{value}); err == nil {
			t.Errorf("%q was accepted", value)
		}
	}
}

func TestLeakTrafficCovers(t *testing.T) {
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
	} {
		traffic, ok := parseLeakTraffic(c.value)
		if !ok {
			t.Errorf("%q was not parsed", c.value)
			continue
		}
		if got := traffic.covers(c.protocol, c.port); got != c.covers {
			t.Errorf("%q covers %s/%d = %v", c.value, c.protocol, c.port, got)
		}
	}
}
