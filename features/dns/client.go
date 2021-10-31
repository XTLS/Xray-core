package dns

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
)

// IPOption is an object for IP query options.
type IPOption struct {
	IPv4Enable bool
	IPv6Enable bool
	FakeEnable bool
}

// Client is a Xray feature for querying DNS information.
//
// xray:api:stable
type Client interface {
	features.Feature

	// LookupIP returns IP address for the given domain. IPs may contain IPv4 and/or IPv6 addresses.
	LookupIP(domain string, option IPOption) ([]net.IP, error)
}

type HostsLookup interface {
	LookupHosts(domain string) *net.Address
}

// ClientType returns the type of Client interface. Can be used for implementing common.HasType.
//
// xray:api:beta
func ClientType() interface{} {
	return (*Client)(nil)
}

// ErrEmptyResponse indicates that DNS query succeeded but no answer was returned.
var ErrEmptyResponse = errors.New("empty response")

type RCodeError uint16

func (e RCodeError) Error() string {
	return serial.Concat("rcode: ", uint16(e))
}

func RCodeFromError(err error) uint16 {
	if err == nil {
		return 0
	}
	cause := errors.Cause(err)
	if r, ok := cause.(RCodeError); ok {
		return uint16(r)
	}
	return 0
}
