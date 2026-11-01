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
	for _, value := range []string{"", "ip", "tcp", "tcp/", "tcp/0", "udp/65536", "tcp/-1", "tcp/+53", "tcp/53/1", "udp/abc", "icmp/1", "tcp:53", " dns"} {
		if _, err := ExpandWfpBlockLeak([]string{value}); err == nil {
			t.Errorf("%q was accepted", value)
		}
	}
}
