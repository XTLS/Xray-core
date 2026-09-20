package dns

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

func Test_parseResponse(t *testing.T) {
	var p [][]byte

	ans := new(dns.Msg)
	ans.Id = 0
	p = append(p, common.Must2(ans.Pack()))

	p = append(p, []byte{})

	ans = new(dns.Msg)
	ans.Id = 1
	ans.Answer = append(
		ans.Answer,
		common.Must2(dns.NewRR("google.com. IN CNAME m.test.google.com")),
		common.Must2(dns.NewRR("google.com. IN CNAME fake.google.com")),
		common.Must2(dns.NewRR("google.com. IN A 8.8.8.8")),
		common.Must2(dns.NewRR("google.com. IN A 8.8.4.4")),
	)
	p = append(p, common.Must2(ans.Pack()))

	ans = new(dns.Msg)
	ans.Id = 2
	ans.Answer = append(
		ans.Answer,
		common.Must2(dns.NewRR("google.com. IN CNAME m.test.google.com")),
		common.Must2(dns.NewRR("google.com. IN CNAME fake.google.com")),
		common.Must2(dns.NewRR("google.com. IN CNAME m.test.google.com")),
		common.Must2(dns.NewRR("google.com. IN CNAME test.google.com")),
		common.Must2(dns.NewRR("google.com. IN AAAA 2001:4860:4860::8888")),
		common.Must2(dns.NewRR("google.com. IN AAAA 2001:4860:4860::8844")),
	)
	p = append(p, common.Must2(ans.Pack()))

	tests := []struct {
		name    string
		want    *IPRecord
		wantErr bool
	}{
		{
			"empty",
			&IPRecord{0, []net.IP(nil), time.Time{}, dnsmessage.RCodeSuccess, nil},
			false,
		},
		{
			"error",
			nil,
			true,
		},
		{
			"a record",
			&IPRecord{
				1,
				[]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
				time.Time{},
				dnsmessage.RCodeSuccess,
				nil,
			},
			false,
		},
		{
			"aaaa record",
			&IPRecord{2, []net.IP{net.ParseIP("2001:4860:4860::8888"), net.ParseIP("2001:4860:4860::8844")}, time.Time{}, dnsmessage.RCodeSuccess, nil},
			false,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseResponse(p[i])
			if (err != nil) != tt.wantErr {
				t.Errorf("handleResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != nil {
				// reset the time and RawHeader
				got.Expire = time.Time{}
				got.RawHeader = nil
			}
			if cmp.Diff(got, tt.want) != "" {
				t.Error(cmp.Diff(got, tt.want))
				// t.Errorf("handleResponse() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func Test_buildReqMsgs(t *testing.T) {
	stubID := func() uint16 {
		return uint16(rand.Uint32())
	}
	type args struct {
		domain  string
		option  dns_feature.IPOption
		reqOpts *dnsmessage.Resource
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"dual stack", args{"test.com", dns_feature.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}, nil}, 2},
		{"ipv4 only", args{"test.com", dns_feature.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: false,
		}, nil}, 1},
		{"ipv6 only", args{"test.com", dns_feature.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: false,
		}, nil}, 1},
		{"none/error", args{"test.com", dns_feature.IPOption{
			IPv4Enable: false,
			IPv6Enable: false,
			FakeEnable: false,
		}, nil}, 0},
		{"name too long", args{strings.Repeat("a", 256), dns_feature.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}, nil}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := buildReqMsgs(tt.args.domain, tt.args.option, stubID, tt.args.reqOpts); !(len(got) == tt.want) {
				t.Errorf("buildReqMsgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_genEDNS0Options(t *testing.T) {
	tests := []struct {
		name   string
		ip     net.IP
		prefix int
		want   []byte
	}{
		{"absent", nil, 0, nil},
		{"IPv4 default", net.IP{1, 2, 3, 4}, 24, []byte{0, 1, 24, 0, 1, 2, 3}},
		{"IPv4 partial byte", net.IP{1, 2, 3, 4}, 20, []byte{0, 1, 20, 0, 1, 2, 0}},
		{"IPv4 full", net.IP{1, 2, 3, 4}, 32, []byte{0, 1, 32, 0, 1, 2, 3, 4}},
		{"IPv4 wildcard", net.IP{0, 0, 0, 0}, 0, []byte{0, 1, 0, 0}},
		{"IPv6 default", net.ParseIP("2001:db8::1"), 96, []byte{0, 2, 96, 0, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"IPv6 full", net.ParseIP("2001:db8::1"), 128, append([]byte{0, 2, 128, 0}, net.ParseIP("2001:db8::1")...)},
		{"IPv6 partial byte", net.ParseIP("2001:db8:1234:5678::1"), 53, []byte{0, 2, 53, 0, 0x20, 1, 0x0d, 0xb8, 0x12, 0x34, 0x50}},
		{"IPv6 wildcard", net.ParseIP("::"), 0, []byte{0, 2, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := genEDNS0Options(tt.ip, tt.prefix, 0)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("unexpected EDNS option: %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("missing EDNS option")
			}
			options := got.Body.(*dnsmessage.OPTResource).Options
			if len(options) != 1 || options[0].Code != 8 || !bytes.Equal(options[0].Data, tt.want) {
				t.Errorf("options = %v, want ECS %v", options, tt.want)
			}
		})
	}
}

func TestClientIPForNameServer(t *testing.T) {
	zero, tooLong := uint32(0), uint32(33)
	global := net.IP{1, 2, 3, 4}
	tests := []struct {
		name       string
		globalIP   net.IP
		globalBits *uint32
		server     *NameServer
		wantIP     net.IP
		wantBits   int
		wantErr    bool
	}{
		{"no ECS", nil, nil, &NameServer{}, nil, 0, false},
		{"legacy global", global, nil, &NameServer{}, global, 24, false},
		{"legacy zero IPv4", net.IP{0, 0, 0, 0}, nil, &NameServer{}, net.IP{0, 0, 0, 0}, 24, false},
		{"legacy IPv6", net.ParseIP("2001:db8::1"), nil, &NameServer{}, net.ParseIP("2001:db8::1"), 96, false},
		{"global wildcard", global, &zero, &NameServer{}, global, 0, false},
		{"server bare overrides prefix", global, &zero, &NameServer{ClientIp: []byte{5, 6, 7, 8}}, net.IP{5, 6, 7, 8}, 24, false},
		{"server IPv6 overrides prefix", global, &zero, &NameServer{ClientIp: net.ParseIP("2001:db8::1")}, net.ParseIP("2001:db8::1"), 96, false},
		{"server wildcard", global, nil, &NameServer{ClientIp: []byte{5, 6, 7, 8}, ClientIpPrefix: &zero}, net.IP{5, 6, 7, 8}, 0, false},
		{"invalid prefix", global, &tooLong, &NameServer{}, nil, 0, true},
		{"prefix without IP", nil, &zero, &NameServer{}, nil, 0, true},
		{"server prefix without IP", global, nil, &NameServer{ClientIpPrefix: &zero}, nil, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, bits, err := clientIPForNameServer(tt.globalIP, tt.globalBits, tt.server)
			if (err != nil) != tt.wantErr || err == nil && (!bytes.Equal(ip, tt.wantIP) || bits != tt.wantBits) {
				t.Errorf("got %v/%d, %v; want %v/%d, error=%t", ip, bits, err, tt.wantIP, tt.wantBits, tt.wantErr)
			}
		})
	}
}

func TestFqdn(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"with fqdn", args{"www.example.com."}, "www.example.com."},
		{"without fqdn", args{"www.example.com"}, "www.example.com."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Fqdn(tt.args.domain); got != tt.want {
				t.Errorf("Fqdn() = %v, want %v", got, tt.want)
			}
		})
	}
}
