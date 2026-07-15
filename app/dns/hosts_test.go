package dns_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

func TestStaticHosts(t *testing.T) {
	pb := []*Config_HostMapping{
		{
			Domain:        &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "lan"}}},
			ProxiedDomain: "#3",
		},
		{
			Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "example.com"}}},
			Ip: [][]byte{
				{1, 1, 1, 1},
			},
		},
		{
			Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "proxy.xray.com"}}},
			Ip: [][]byte{
				{1, 2, 3, 4},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
			ProxiedDomain: "another-proxy.xray.com",
		},
		{
			Domain:        &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "proxy2.xray.com"}}},
			ProxiedDomain: "proxy.xray.com",
		},
		{
			Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "example.cn"}}},
			Ip: [][]byte{
				{2, 2, 2, 2},
			},
		},
		{
			Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "baidu.com"}}},
			Ip: [][]byte{
				{127, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
	}

	hosts, err := NewStaticHosts(pb)
	common.Must(err)

	{
		_, err := hosts.Lookup("example.com.lan", dns.IPOption{})
		if dns.RCodeFromError(err) != 3 {
			t.Error(err)
		}
	}

	{
		ips, _ := hosts.Lookup("example.com", dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
		})
		if len(ips) != 1 {
			t.Error("expect 1 IP, but got ", len(ips))
		}
		if diff := cmp.Diff([]byte(ips[0].IP()), []byte{1, 1, 1, 1}); diff != "" {
			t.Error(diff)
		}
	}

	{
		domain, _ := hosts.Lookup("proxy.xray.com", dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
		})
		if len(domain) != 1 {
			t.Error("expect 1 domain, but got ", len(domain))
		}
		if diff := cmp.Diff(domain[0].Domain(), "another-proxy.xray.com"); diff != "" {
			t.Error(diff)
		}
	}

	{
		domain, _ := hosts.Lookup("proxy2.xray.com", dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
		})
		if len(domain) != 1 {
			t.Error("expect 1 domain, but got ", len(domain))
		}
		if diff := cmp.Diff(domain[0].Domain(), "another-proxy.xray.com"); diff != "" {
			t.Error(diff)
		}
	}

	{
		ips, _ := hosts.Lookup("www.example.cn", dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
		})
		if len(ips) != 1 {
			t.Error("expect 1 IP, but got ", len(ips))
		}
		if diff := cmp.Diff([]byte(ips[0].IP()), []byte{2, 2, 2, 2}); diff != "" {
			t.Error(diff)
		}
	}

	{
		ips, _ := hosts.Lookup("baidu.com", dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
		})
		if len(ips) != 1 {
			t.Error("expect 1 IP, but got ", len(ips))
		}
		if diff := cmp.Diff([]byte(ips[0].IP()), []byte(net.LocalHostIPv6.IP())); diff != "" {
			t.Error(diff)
		}
	}
}

func TestStaticHostsCycle(t *testing.T) {
	full := func(domain string) *geodata.DomainRule {
		return &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: domain}}}
	}
	pb := []*Config_HostMapping{
		{Domain: full("a.xray.com"), ProxiedDomain: "b.xray.com"},
		{Domain: full("b.xray.com"), ProxiedDomain: "a.xray.com"},
		{Domain: full("self.xray.com"), ProxiedDomain: "self.xray.com"},
		{Domain: full("c1.xray.com"), ProxiedDomain: "C2.XRAY.COM"},
		{Domain: full("c2.xray.com"), ProxiedDomain: "c1.xray.com"},
		{Domain: full("hop1.xray.com"), ProxiedDomain: "hop2.xray.com"},
		{Domain: full("hop2.xray.com"), ProxiedDomain: "hop3.xray.com"},
		{Domain: full("hop3.xray.com"), ProxiedDomain: "hop4.xray.com"},
		{Domain: full("hop4.xray.com"), ProxiedDomain: "hop5.xray.com"},
		{Domain: full("hop5.xray.com"), ProxiedDomain: "hop6.xray.com"},
		{Domain: full("hop6.xray.com"), ProxiedDomain: "hop7.xray.com"},
		{Domain: full("hop7.xray.com"), Ip: [][]byte{{9, 9, 9, 9}}},
	}

	hosts, err := NewStaticHosts(pb)
	common.Must(err)

	opt := dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	}

	{
		// A cyclic mapping must not fail the lookup; the wrapped domain is
		// returned so resolution falls through to the name servers.
		addrs, err := hosts.Lookup("a.xray.com", opt)
		if err != nil {
			t.Error("two-domain cycle should not error, but got: ", err)
		}
		if len(addrs) != 1 || !addrs[0].Family().IsDomain() {
			t.Error("expect 1 domain address for cyclic mapping, but got ", addrs)
		}
	}

	{
		// A self-referencing mapping must not fail either.
		addrs, err := hosts.Lookup("self.xray.com", opt)
		if err != nil {
			t.Error("self-referencing mapping should not error, but got: ", err)
		}
		if len(addrs) != 1 || !addrs[0].Family().IsDomain() {
			t.Error("expect 1 domain address for self-referencing mapping, but got ", addrs)
		}
	}

	{
		// Cycle detection must be case-insensitive.
		addrs, err := hosts.Lookup("c1.xray.com", opt)
		if err != nil {
			t.Error("mixed-case cycle should not error, but got: ", err)
		}
		if len(addrs) != 1 || !addrs[0].Family().IsDomain() {
			t.Error("expect 1 domain address for mixed-case cyclic mapping, but got ", addrs)
		}
	}

	{
		// An acyclic chain longer than the old depth limit of 5 unwraps completely.
		ips, err := hosts.Lookup("hop1.xray.com", opt)
		if err != nil {
			t.Error("long acyclic chain should not error, but got: ", err)
		}
		if len(ips) != 1 {
			t.Error("expect 1 IP, but got ", len(ips))
		} else if !ips[0].Family().IsIP() {
			t.Error("expect an IP address, but got domain ", ips[0].Domain())
		} else if diff := cmp.Diff([]byte(ips[0].IP()), []byte{9, 9, 9, 9}); diff != "" {
			t.Error(diff)
		}
	}
}
