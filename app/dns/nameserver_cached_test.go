package dns

import (
	go_errors "errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

func TestMerge(t *testing.T) {
	ip4 := net.ParseIP("192.0.2.1")
	ip6 := net.ParseIP("2001:db8::1")

	rec4 := &IPRecord{
		IP:     []net.IP{ip4},
		Expire: time.Now().Add(60 * time.Second),
		RCode:  dnsmessage.RCodeSuccess,
	}
	rec6 := &IPRecord{
		IP:     []net.IP{ip6},
		Expire: time.Now().Add(120 * time.Second),
		RCode:  dnsmessage.RCodeSuccess,
	}

	t.Run("IPv4OnlyRequest", func(t *testing.T) {
		opt := dns.IPOption{IPv4Enable: true, IPv6Enable: false}
		ips, ttl, err := merge(opt, rec4, rec6)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(ips) != 1 || !ips[0].Equal(ip4) {
			t.Fatalf("expected [%v], got %v", ip4, ips)
		}
		if ttl <= 0 || ttl > 60 {
			t.Fatalf("expected ttl <= 60, got %v", ttl)
		}
	})

	t.Run("IPv6OnlyRequest", func(t *testing.T) {
		opt := dns.IPOption{IPv4Enable: false, IPv6Enable: true}
		ips, ttl, err := merge(opt, rec4, rec6)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(ips) != 1 || !ips[0].Equal(ip6) {
			t.Fatalf("expected [%v], got %v", ip6, ips)
		}
		if ttl <= 0 || ttl > 120 {
			t.Fatalf("expected ttl <= 120, got %v", ttl)
		}
	})

	t.Run("DualStackBothExist", func(t *testing.T) {
		opt := dns.IPOption{IPv4Enable: true, IPv6Enable: true}
		ips, ttl, err := merge(opt, rec4, rec6)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(ips) != 2 {
			t.Fatalf("expected 2 IPs, got %v", ips)
		}
		if ttl <= 0 || ttl > 60 {
			t.Fatalf("expected ttl <= 60 (min ttl), got %v", ttl)
		}
	})

	t.Run("DualStackIPv4OnlyDomain", func(t *testing.T) {
		opt := dns.IPOption{IPv4Enable: true, IPv6Enable: true}
		ips, ttl, err := merge(opt, rec4, nil)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(ips) != 1 || !ips[0].Equal(ip4) {
			t.Fatalf("expected [%v], got %v", ip4, ips)
		}
		if ttl <= 0 || ttl > 60 {
			t.Fatalf("expected ttl <= 60, got %v", ttl)
		}
	})

	t.Run("DualStackIPv6OnlyDomain", func(t *testing.T) {
		opt := dns.IPOption{IPv4Enable: true, IPv6Enable: true}
		ips, ttl, err := merge(opt, nil, rec6)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(ips) != 1 || !ips[0].Equal(ip6) {
			t.Fatalf("expected [%v], got %v", ip6, ips)
		}
		if ttl <= 0 || ttl > 120 {
			t.Fatalf("expected ttl <= 120, got %v", ttl)
		}
	})

	t.Run("DualStackNeitherExist", func(t *testing.T) {
		opt := dns.IPOption{IPv4Enable: true, IPv6Enable: true}
		ips, ttl, err := merge(opt, nil, nil)
		if !go_errors.Is(err, errRecordNotFound) {
			t.Fatalf("expected errRecordNotFound, got %v", err)
		}
		if len(ips) != 0 {
			t.Fatalf("expected nil/empty ips, got %v", ips)
		}
		if ttl != 0 {
			t.Fatalf("expected ttl 0, got %v", ttl)
		}
	})
}
