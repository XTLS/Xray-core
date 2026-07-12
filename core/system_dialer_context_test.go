package core

import (
	"context"
	"errors"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

type instanceDNSClient struct {
	ip     xnet.IP
	closed bool
}

func (*instanceDNSClient) Type() interface{} {
	return dns.ClientType()
}

func (*instanceDNSClient) Start() error {
	return nil
}

func (c *instanceDNSClient) Close() error {
	c.closed = true
	return nil
}

func (c *instanceDNSClient) LookupIP(string, dns.IPOption) ([]xnet.IP, uint32, error) {
	if c.closed {
		return nil, 0, errors.New("DNS client is closed")
	}
	return []xnet.IP{c.ip}, dns.DefaultTTL, nil
}

func TestSystemDialerDependenciesAreInstanceScoped(t *testing.T) {
	mainDNS := &instanceDNSClient{ip: xnet.ParseIP("192.0.2.1")}
	testDNS := &instanceDNSClient{ip: xnet.ParseIP("192.0.2.2")}
	mainInstance := &Instance{}
	testInstance := &Instance{}

	// Core features retain contexts while the instance is still under
	// construction, before its DNS client and outbound manager are registered.
	mainContext := toContext(context.Background(), mainInstance)
	testContext := toContext(context.Background(), testInstance)
	if err := mainInstance.AddFeature(mainDNS); err != nil {
		t.Fatal(err)
	}
	if err := testInstance.AddFeature(testDNS); err != nil {
		t.Fatal(err)
	}

	if err := testDNS.Close(); err != nil {
		t.Fatal(err)
	}

	ips, err := internet.LookupForIPWithContext(mainContext, "example.com", internet.DomainStrategy_USE_IP, nil)
	if err != nil {
		t.Fatalf("main instance lookup failed after test instance closed: %v", err)
	}
	if got, want := ips[0].String(), mainDNS.ip.String(); got != want {
		t.Fatalf("main instance used the wrong DNS client: got %s, want %s", got, want)
	}

	if _, err := internet.LookupForIPWithContext(testContext, "example.com", internet.DomainStrategy_USE_IP, nil); err == nil {
		t.Fatal("closed test instance DNS client unexpectedly remained usable")
	}
}

func TestCoreInitializesLegacySystemDialerFallback(t *testing.T) {
	internet.InitSystemDialer(nil, nil)
	t.Cleanup(func() {
		internet.InitSystemDialer(nil, nil)
	})

	instance, err := New(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})

	ips, err := internet.LookupForIP("localhost", internet.DomainStrategy_USE_IP, nil)
	if err != nil {
		t.Fatalf("legacy system dialer lookup was not initialized by core construction: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("legacy system dialer lookup returned no addresses")
	}
}
