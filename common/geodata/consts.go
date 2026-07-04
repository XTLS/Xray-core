package geodata

import (
	"sync"

	"github.com/xtls/xray-core/common"
)

var privateIPMatcher = sync.OnceValue(func() IPMatcher {
	return common.Must2(IPReg.BuildIPMatcher(common.Must2(ParseIPRules([]string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/3",
		"::/127",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}))))
})

func GetPrivateIPMatcher() IPMatcher { return privateIPMatcher() }

var privateDomainMatcher = sync.OnceValue(func() DomainMatcher {
	return common.Must2(DomainReg.BuildDomainMatcher(common.Must2(ParseDomainRules([]string{
		"lan",
		"localdomain",
		"example",
		"invalid",
		"localhost",
		"test",
		"local",
		"home.arpa",
		"internal",
		"regexp:^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", // Dotless domains
	}, Domain_Domain))))
})

func GetPrivateDomainMatcher() DomainMatcher { return privateDomainMatcher() }
