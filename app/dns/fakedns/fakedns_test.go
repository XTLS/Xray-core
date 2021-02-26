package fakedns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
)

func TestNewFakeDnsHolder(_ *testing.T) {
	_, err := NewFakeDNSHolder()
	common.Must(err)
}

func TestFakeDnsHolderCreateMapping(t *testing.T) {
	fkdns, err := NewFakeDNSHolder()
	common.Must(err)

	addr := fkdns.GetFakeIPForDomain("fakednstest.v2fly.org")
	assert.Equal(t, "240.0.0.0", addr[0].IP().String())
}

func TestFakeDnsHolderCreateMappingMany(t *testing.T) {
	fkdns, err := NewFakeDNSHolder()
	common.Must(err)

	addr := fkdns.GetFakeIPForDomain("fakednstest.v2fly.org")
	assert.Equal(t, "240.0.0.0", addr[0].IP().String())

	addr2 := fkdns.GetFakeIPForDomain("fakednstest2.v2fly.org")
	assert.Equal(t, "240.0.0.1", addr2[0].IP().String())
}

func TestFakeDnsHolderCreateMappingManyAndResolve(t *testing.T) {
	fkdns, err := NewFakeDNSHolder()
	common.Must(err)

	{
		addr := fkdns.GetFakeIPForDomain("fakednstest.v2fly.org")
		assert.Equal(t, "240.0.0.0", addr[0].IP().String())
	}

	{
		addr2 := fkdns.GetFakeIPForDomain("fakednstest2.v2fly.org")
		assert.Equal(t, "240.0.0.1", addr2[0].IP().String())
	}

	{
		result := fkdns.GetDomainFromFakeDNS(net.ParseAddress("240.0.0.0"))
		assert.Equal(t, "fakednstest.v2fly.org", result)
	}

	{
		result := fkdns.GetDomainFromFakeDNS(net.ParseAddress("240.0.0.1"))
		assert.Equal(t, "fakednstest2.v2fly.org", result)
	}
}

func TestFakeDnsHolderCreateMappingManySingleDomain(t *testing.T) {
	fkdns, err := NewFakeDNSHolder()
	common.Must(err)

	addr := fkdns.GetFakeIPForDomain("fakednstest.v2fly.org")
	assert.Equal(t, "240.0.0.0", addr[0].IP().String())

	addr2 := fkdns.GetFakeIPForDomain("fakednstest.v2fly.org")
	assert.Equal(t, "240.0.0.0", addr2[0].IP().String())
}

func TestFakeDnsHolderCreateMappingAndRollOver(t *testing.T) {
	fkdns, err := NewFakeDNSHolderConfigOnly(&FakeDnsPool{
		IpPool:  "240.0.0.0/12",
		LruSize: 256,
	})
	common.Must(err)

	err = fkdns.Start()

	common.Must(err)

	{
		addr := fkdns.GetFakeIPForDomain("fakednstest.v2fly.org")
		assert.Equal(t, "240.0.0.0", addr[0].IP().String())
	}

	{
		addr2 := fkdns.GetFakeIPForDomain("fakednstest2.v2fly.org")
		assert.Equal(t, "240.0.0.1", addr2[0].IP().String())
	}

	for i := 0; i <= 8192; i++ {
		{
			result := fkdns.GetDomainFromFakeDNS(net.ParseAddress("240.0.0.0"))
			assert.Equal(t, "fakednstest.v2fly.org", result)
		}

		{
			result := fkdns.GetDomainFromFakeDNS(net.ParseAddress("240.0.0.1"))
			assert.Equal(t, "fakednstest2.v2fly.org", result)
		}

		{
			uuid := uuid.New()
			domain := uuid.String() + ".fakednstest.v2fly.org"
			addr := fkdns.GetFakeIPForDomain(domain)
			rsaddr := addr[0].IP().String()

			result := fkdns.GetDomainFromFakeDNS(net.ParseAddress(rsaddr))
			assert.Equal(t, domain, result)
		}
	}
}
