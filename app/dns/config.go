package dns

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
)

// References:
// https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml
// https://unix.stackexchange.com/questions/92441/whats-the-difference-between-local-home-and-lan
var localTLDsAndDotlessDomainsRules = []*geodata.DomainRule{
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Regex, Value: "^[^.]+$"}}}, // This will only match domains without any dot
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "local"}}},
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "localdomain"}}},
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "localhost"}}},
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "lan"}}},
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "home.arpa"}}},
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "example"}}},
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "invalid"}}},
	{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "test"}}},
}

func toNetIP(addrs []net.Address) ([]net.IP, error) {
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Family().IsIP() {
			ips = append(ips, addr.IP())
		} else {
			return nil, errors.New("Failed to convert address", addr, "to Net IP.").AtWarning()
		}
	}
	return ips, nil
}

func generateRandomTag() string {
	id := uuid.New()
	return "xray.system." + id.String()
}
