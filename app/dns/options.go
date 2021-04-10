package dns

import "github.com/xtls/xray-core/features/dns"

func isIPQuery(o *dns.IPOption) bool {
	return o.IPv4Enable || o.IPv6Enable
}

func canQueryOnClient(o *dns.IPOption, c *Client) bool {
	isIPClient := !(c.Name() == FakeDNSName)
	return isIPClient && isIPQuery(o)
}

func isQuery(o *dns.IPOption) bool {
	return !(o.IPv4Enable || o.IPv6Enable || o.FakeEnable)
}
