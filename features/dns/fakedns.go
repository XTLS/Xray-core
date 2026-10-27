package dns

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features"
)

type FakeDNSEngine interface {
	features.Feature
	GetFakeIPForDomain(domain string) []net.Address
	GetDomainFromFakeDNS(ip net.Address) string
}

var (
	FakeIPv4Pool = "198.18.0.0/15"
	FakeIPv6Pool = "2001:2::/48"
)

type FakeDNSEngineRev0 interface {
	FakeDNSEngine
	IsIPInIPPool(ip net.Address) bool
	GetFakeIPForDomain3(domain string, IPv4, IPv6 bool) []net.Address
}

// FakeDNSPoolStats counts retained address-family mappings, not active connections.
// It contains no domains or individual allocated addresses.
type FakeDNSPoolStats struct {
	IPPool   string `json:"ipPool"`
	Used     uint64 `json:"used"`
	Capacity uint64 `json:"capacity"`
}

// FakeDNSStatsProvider is an optional, read-only local allocator capability.
// Snapshots must not allocate mappings or change LRU recency. A nil snapshot
// means statistics are unavailable, for example before the pools start.
type FakeDNSStatsProvider interface {
	GetFakeDNSStats() []FakeDNSPoolStats
}
