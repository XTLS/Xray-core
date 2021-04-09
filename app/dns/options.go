package dns

import "github.com/xtls/xray-core/features/dns"

type Option interface {
	queryIPv4() bool
	queryIPv6() bool
	queryIP() bool
	queryFake() bool
	canDoQuery(c *Client) bool
}

func isIPQuery(o dns.IPOption) bool {
	return o.IPv4Enable || o.IPv6Enable
}

func canQueryOnClient(o dns.IPOption, c *Client) bool {
	isIPClient := !(c.Name() == FakeDNSName)
	return isIPClient && isIPQuery(o)
}

func isQuery(o dns.IPOption) bool {
	return !(o.IPv4Enable || o.IPv6Enable || o.FakeEnable)
}
