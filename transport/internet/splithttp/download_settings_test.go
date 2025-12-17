package splithttp

import (
	"testing"

	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestXHTTPDownloadEnableDNSPin(t *testing.T) {
	if xhttpDownloadEnableDNSPin(nil) {
		t.Fatal("expected false for nil downloadCfg")
	}
	if !xhttpDownloadEnableDNSPin(&internet.StreamConfig{Address: nil}) {
		t.Fatal("expected true for nil address")
	}
	if !xhttpDownloadEnableDNSPin(&internet.StreamConfig{Address: cnet.NewIPOrDomain(cnet.DomainAddress(""))}) {
		t.Fatal("expected true for empty domain")
	}
	if !xhttpDownloadEnableDNSPin(&internet.StreamConfig{Address: cnet.NewIPOrDomain(cnet.DomainAddress("same"))}) {
		t.Fatal(`expected true for domain "same"`)
	}
	if !xhttpDownloadEnableDNSPin(&internet.StreamConfig{Address: cnet.NewIPOrDomain(cnet.DomainAddress("SAME"))}) {
		t.Fatal(`expected true for domain "SAME" (case-insensitive)`)
	}
	if xhttpDownloadEnableDNSPin(&internet.StreamConfig{Address: cnet.NewIPOrDomain(cnet.DomainAddress("other.example"))}) {
		t.Fatal("expected false for non-same domain")
	}
}

func TestXHTTPApplyDownloadSameAddress_InheritsPrimaryAddressAndKeepsPort(t *testing.T) {
	primary := cnet.TCPDestination(cnet.DomainAddress("example.com"), 443)

	// Case: downloadCfg has nil address; memory2 has no destination.
	{
		downloadCfg := &internet.StreamConfig{Port: 8443, Address: nil}
		memory2 := &internet.MemoryStreamConfig{}
		xhttpApplyDownloadSameAddress(primary, downloadCfg, memory2)
		if memory2.Destination == nil {
			t.Fatal("expected destination to be filled")
		}
		if memory2.Destination.Address.String() != primary.Address.String() {
			t.Fatalf("expected inherited address %s, got %s", primary.Address, memory2.Destination.Address)
		}
		if memory2.Destination.Port != cnet.Port(8443) {
			t.Fatalf("expected port 8443, got %s", memory2.Destination.Port)
		}
	}

	// Case: downloadCfg address is "same"; memory2 destination initially points to "same".
	{
		downloadCfg := &internet.StreamConfig{Port: 8443, Address: cnet.NewIPOrDomain(cnet.DomainAddress("same"))}
		memory2 := &internet.MemoryStreamConfig{
			Destination: &cnet.Destination{Address: cnet.DomainAddress("same"), Port: 1, Network: cnet.Network_TCP},
		}
		xhttpApplyDownloadSameAddress(primary, downloadCfg, memory2)
		if memory2.Destination.Address.String() != primary.Address.String() {
			t.Fatalf("expected inherited address %s, got %s", primary.Address, memory2.Destination.Address)
		}
		if memory2.Destination.Port != cnet.Port(8443) {
			t.Fatalf("expected port 8443, got %s", memory2.Destination.Port)
		}
	}

	// Case: downloadCfg address is explicit other domain -> should not override.
	{
		downloadCfg := &internet.StreamConfig{Port: 8443, Address: cnet.NewIPOrDomain(cnet.DomainAddress("other.example"))}
		memory2 := &internet.MemoryStreamConfig{
			Destination: &cnet.Destination{Address: cnet.DomainAddress("other.example"), Port: 8443, Network: cnet.Network_TCP},
		}
		xhttpApplyDownloadSameAddress(primary, downloadCfg, memory2)
		if memory2.Destination.Address.String() != "other.example" {
			t.Fatalf("expected address to remain other.example, got %s", memory2.Destination.Address)
		}
	}
}


