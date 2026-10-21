package dns_test

import (
	"context"
	"encoding/binary"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

func TestTCPLocalNameServer(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, false, 0, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
}

func TestTCPLocalNameServerLargeResponse(t *testing.T) {
	const answers = 1000 // about 16 KB, more than one buf.Buffer

	l, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var length uint16
				if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
					return
				}
				req := make([]byte, length)
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				var msg dnsmessage.Message
				if err := msg.Unpack(req); err != nil {
					return
				}
				msg.Header.Response = true
				msg.Additionals = nil
				if q := msg.Questions[0]; q.Type == dnsmessage.TypeA {
					for i := range answers {
						msg.Answers = append(msg.Answers, dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
							Body:   &dnsmessage.AResource{A: [4]byte{10, 0, byte(i >> 8), byte(i)}},
						})
					}
				}
				resp, err := msg.Pack()
				if err != nil {
					return
				}
				binary.Write(conn, binary.BigEndian, uint16(len(resp)))
				conn.Write(resp)
			}()
		}
	}()

	url, err := url.Parse("tcp+local://" + l.Addr().String())
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, true, false, 0, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ips, _, err := s.QueryIP(ctx, "example.com", dns_feature.IPOption{
		IPv4Enable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != answers {
		t.Fatalf("expect %d ips, but got %d", answers, len(ips))
	}
}

func TestTCPLocalNameServerWithCache(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, false, 0, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips2, _, err := s.QueryIP(ctx2, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if r := cmp.Diff(ips2, ips); r != "" {
		t.Fatal(r)
	}
}

func TestTCPLocalNameServerWithIPv4Override(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, false, 0, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
	})
	cancel()
	common.Must(err)

	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	for _, ip := range ips {
		if len(ip) != net.IPv4len {
			t.Error("expect only IPv4 response from DNS query")
		}
	}
}

func TestTCPLocalNameServerWithIPv6Override(t *testing.T) {
	url, err := url.Parse("tcp+local://8.8.8.8")
	common.Must(err)
	s, err := NewTCPLocalNameServer(url, false, false, 0, net.IP(nil))
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: false,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)

	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	for _, ip := range ips {
		if len(ip) != net.IPv6len {
			t.Error("expect only IPv6 response from DNS query")
		}
	}
}
