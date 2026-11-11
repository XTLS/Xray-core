package dns

import (
	"context"
	gonet "net"
	"net/url"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

func TestUDPLocalNameServerAddress(t *testing.T) {
	tests := []struct {
		rawURL  string
		address string
		port    net.Port
	}{
		{"udp+local://127.0.0.1", "127.0.0.1", 53},
		{"udp+local://127.0.0.1:5353", "127.0.0.1", 5353},
		{"udp+local://[::1]:5300", "::1", 5300},
	}
	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatal(err)
			}
			s, err := NewUDPLocalNameServer(u, false, false, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.address.Address.String(); got != tt.address {
				t.Errorf("address = %q, want %q", got, tt.address)
			}
			if got := s.address.Port; got != tt.port {
				t.Errorf("port = %d, want %d", got, tt.port)
			}
		})
	}
}

func TestUDPLocalNameServerInvalidAddress(t *testing.T) {
	for _, rawURL := range []string{"udp+local://", "udp+local://127.0.0.1:65536"} {
		t.Run(rawURL, func(t *testing.T) {
			u, err := url.Parse(rawURL)
			if err != nil {
				return
			}
			if _, err := NewUDPLocalNameServer(u, false, false, 0, nil); err == nil {
				t.Fatal("expected invalid server address error")
			}
		})
	}
}

func TestUDPLocalNameServerWithoutDispatcher(t *testing.T) {
	listener, err := gonet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 4096)
		for {
			n, remote, err := listener.ReadFrom(packet)
			if err != nil {
				return
			}
			query := new(dns.Msg)
			if err := query.Unpack(packet[:n]); err != nil {
				continue
			}
			response := new(dns.Msg)
			response.SetReply(query)
			for _, question := range query.Question {
				header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
				switch question.Qtype {
				case dns.TypeA:
					response.Answer = append(response.Answer, &dns.A{Hdr: header, A: gonet.IPv4(203, 0, 113, 10)})
				case dns.TypeAAAA:
					response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: gonet.ParseIP("2001:db8::10")})
				}
			}
			wire, err := response.Pack()
			if err == nil {
				_, _ = listener.WriteTo(wire, remote)
			}
		}
	}()
	defer func() {
		_ = listener.Close()
		<-done
	}()

	dest := net.UDPDestination(net.DomainAddress("udp+local://"+listener.LocalAddr().String()), 0)
	s, err := NewServer(context.Background(), dest, nil, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, _, err := s.QueryIP(ctx, "example.com", dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool)
	for _, ip := range ips {
		got[ip.String()] = true
	}
	if !got["203.0.113.10"] || !got["2001:db8::10"] {
		t.Errorf("unexpected DNS answers: %v", ips)
	}
}
