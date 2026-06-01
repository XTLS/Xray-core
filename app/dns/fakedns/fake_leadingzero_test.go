package fakedns

import (
	"testing"
)

// TestFakeDNSLeadingZeroPool covers IP pools whose network base begins with a
// zero byte, e.g. the NAT64 prefix 64:ff9b::/96. big.Int.Bytes() strips the
// leading zero, so the generated IP used to come back nil/short, corrupting the
// answer (and looping forever once the nil value was cached).
func TestFakeDNSLeadingZeroPool(t *testing.T) {
	fkdns, err := NewFakeDNSHolderConfigOnly(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fkdns.initialize("64:ff9b::/96", 65535); err != nil {
		t.Fatal(err)
	}

	ips := fkdns.GetFakeIPForDomain("example.com")
	if len(ips) != 1 {
		t.Fatalf("expected 1 ip, got %d", len(ips))
	}
	ip := ips[0]
	if ip == nil || !ip.Family().IsIP() {
		t.Fatalf("got invalid fake ip: %v", ip)
	}
	if !fkdns.IsIPInIPPool(ip) {
		t.Errorf("fake ip %v is not inside the pool", ip)
	}
	if got := fkdns.GetDomainFromFakeDNS(ip); got != "example.com" {
		t.Errorf("reverse lookup = %q, want example.com", got)
	}
}
