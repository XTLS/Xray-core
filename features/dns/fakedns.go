package dns

import (
	"github.com/jobberrt/xray-core/common/net"
	"github.com/jobberrt/xray-core/features"
)

type FakeDNSEngine interface {
	features.Feature
	GetFakeIPForDomain(domain string) []net.Address
	GetDomainFromFakeDNS(ip net.Address) string
}

var (
	FakeIPv4Pool = "198.18.0.0/15"
	FakeIPv6Pool = "fc00::/18"
)

type FakeDNSEngineRev0 interface {
	FakeDNSEngine
	IsIPInIPPool(ip net.Address) bool
	GetFakeIPForDomain3(domain string, IPv4, IPv6 bool) []net.Address
}
