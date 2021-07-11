package dns

import (
	dm "github.com/xtls/xray-core/common/matcher/domain"
	"github.com/xtls/xray-core/common/matcher/str"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
)

var typeMap = map[dm.MatchingType]str.Type{
	dm.MatchingType_Keyword:   str.Substr,
	dm.MatchingType_Regex:     str.Regex,
	dm.MatchingType_Subdomain: str.Domain,
	dm.MatchingType_Full:      str.Full,
}

// References:
// https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml
// https://unix.stackexchange.com/questions/92441/whats-the-difference-between-local-home-and-lan
var localTLDsAndDotlessDomains = []*dm.Domain{
	{Type: dm.MatchingType_Regex, Value: "^[^.]+$"}, // This will only match domains without any dot
	{Type: dm.MatchingType_Subdomain, Value: "local"},
	{Type: dm.MatchingType_Subdomain, Value: "localdomain"},
	{Type: dm.MatchingType_Subdomain, Value: "localhost"},
	{Type: dm.MatchingType_Subdomain, Value: "lan"},
	{Type: dm.MatchingType_Subdomain, Value: "home.arpa"},
	{Type: dm.MatchingType_Subdomain, Value: "example"},
	{Type: dm.MatchingType_Subdomain, Value: "invalid"},
	{Type: dm.MatchingType_Subdomain, Value: "test"},
}

var localTLDsAndDotlessDomainsRule = &NameServer_OriginalRule{
	Rule: "geosite:private",
	Size: uint32(len(localTLDsAndDotlessDomains)),
}

func toStrMatcher(t dm.MatchingType, domain string) (str.Matcher, error) {
	strMType, f := typeMap[t]
	if !f {
		return nil, newError("unknown mapping type", t).AtWarning()
	}
	matcher, err := strMType.New(domain)
	if err != nil {
		return nil, newError("failed to create str matcher").Base(err)
	}
	return matcher, nil
}

func toNetIP(addrs []net.Address) ([]net.IP, error) {
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Family().IsIP() {
			ips = append(ips, addr.IP())
		} else {
			return nil, newError("Failed to convert address", addr, "to Net IP.").AtWarning()
		}
	}
	return ips, nil
}

func generateRandomTag() string {
	id := uuid.New()
	return "xray.system." + id.String()
}
