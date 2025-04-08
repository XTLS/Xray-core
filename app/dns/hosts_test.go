package dns_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/hosemorinho412/xray-core/app/dns"
	"github.com/hosemorinho412/xray-core/common"
	"github.com/hosemorinho412/xray-core/common/net"
	"github.com/hosemorinho412/xray-core/features/dns"
)

func TestStaticHosts(t *testing.T) {
	pb := []*Config_HostMapping{
		{
			Type:   DomainMatchingType_Full,
			Domain: "example.com",
			Ip: [][]byte{
				{1, 1, 1, 1},
			},
		},
		{
			Type:   DomainMatchingType_Full,
			Domain: "proxy.xray.com",
			Ip: [][]byte{
				{1, 2, 3, 4},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
			ProxiedDomain: "another-proxy.xray.com",
		},
		{
			Type:          DomainMatchingType_Full,
			Domain:        "proxy2.xray.com",
			ProxiedDomain: "proxy.xray.com",
		},
		{
			Type:   DomainMatchingType_Subdomain,
			Domain: "example.cn",
			Ip: [][]byte{
				{2, 2, 2, 2},
			},
		},
		{
			Type:   DomainMatchingType_Subdomain,
			Domain: "baidu.com",
			Ip: [][]byte{
				{127, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
	}

	hosts, err := NewStaticHosts(pb)
	common.Must(err)

	{
		ips := hosts.Lookup("example.com", dns.IPOption{
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
		domain := hosts.Lookup("proxy.xray.com", dns.IPOption{
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
		domain := hosts.Lookup("proxy2.xray.com", dns.IPOption{
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
		ips := hosts.Lookup("www.example.cn", dns.IPOption{
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
		ips := hosts.Lookup("baidu.com", dns.IPOption{
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
