package net_test

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/common/net"
)

func TestAddressProperty(t *testing.T) {
	type addrProprty struct {
		IP     []byte
		Domain string
		Family AddressFamily
		String string
	}

	testCases := []struct {
		Input  Address
		Output addrProprty
	}{
		{
			Input: IPAddress([]byte{byte(1), byte(2), byte(3), byte(4)}),
			Output: addrProprty{
				IP:     []byte{byte(1), byte(2), byte(3), byte(4)},
				Family: AddressFamilyIPv4,
				String: "1.2.3.4",
			},
		},
		{
			Input: IPAddress([]byte{
				byte(1), byte(2), byte(3), byte(4),
				byte(1), byte(2), byte(3), byte(4),
				byte(1), byte(2), byte(3), byte(4),
				byte(1), byte(2), byte(3), byte(4),
			}),
			Output: addrProprty{
				IP: []byte{
					byte(1), byte(2), byte(3), byte(4),
					byte(1), byte(2), byte(3), byte(4),
					byte(1), byte(2), byte(3), byte(4),
					byte(1), byte(2), byte(3), byte(4),
				},
				Family: AddressFamilyIPv6,
				String: "[102:304:102:304:102:304:102:304]",
			},
		},
		{
			Input: IPAddress([]byte{
				byte(0), byte(0), byte(0), byte(0),
				byte(0), byte(0), byte(0), byte(0),
				byte(0), byte(0), byte(255), byte(255),
				byte(1), byte(2), byte(3), byte(4),
			}),
			Output: addrProprty{
				IP:     []byte{byte(1), byte(2), byte(3), byte(4)},
				Family: AddressFamilyIPv4,
				String: "1.2.3.4",
			},
		},
		{
			Input: DomainAddress("example.com"),
			Output: addrProprty{
				Domain: "example.com",
				Family: AddressFamilyDomain,
				String: "example.com",
			},
		},
		{
			Input: IPAddress(net.IPv4(1, 2, 3, 4)),
			Output: addrProprty{
				IP:     []byte{byte(1), byte(2), byte(3), byte(4)},
				Family: AddressFamilyIPv4,
				String: "1.2.3.4",
			},
		},
		{
			Input: ParseAddress("[2001:4860:0:2001::68]"),
			Output: addrProprty{
				IP:     []byte{0x20, 0x01, 0x48, 0x60, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68},
				Family: AddressFamilyIPv6,
				String: "[2001:4860:0:2001::68]",
			},
		},
		{
			Input: ParseAddress("::0"),
			Output: addrProprty{
				IP:     AnyIPv6.IP(),
				Family: AddressFamilyIPv6,
				String: "[::]",
			},
		},
		{
			Input: ParseAddress("[::ffff:123.151.71.143]"),
			Output: addrProprty{
				IP:     []byte{123, 151, 71, 143},
				Family: AddressFamilyIPv4,
				String: "123.151.71.143",
			},
		},
		{
			Input: NewIPOrDomain(ParseAddress("example.com")).AsAddress(),
			Output: addrProprty{
				Domain: "example.com",
				Family: AddressFamilyDomain,
				String: "example.com",
			},
		},
		{
			Input: NewIPOrDomain(ParseAddress("8.8.8.8")).AsAddress(),
			Output: addrProprty{
				IP:     []byte{8, 8, 8, 8},
				Family: AddressFamilyIPv4,
				String: "8.8.8.8",
			},
		},
		{
			Input: NewIPOrDomain(ParseAddress("[2001:4860:0:2001::68]")).AsAddress(),
			Output: addrProprty{
				IP:     []byte{0x20, 0x01, 0x48, 0x60, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68},
				Family: AddressFamilyIPv6,
				String: "[2001:4860:0:2001::68]",
			},
		},
	}

	for _, testCase := range testCases {
		actual := addrProprty{
			Family: testCase.Input.Family(),
			String: testCase.Input.String(),
		}
		if testCase.Input.Family().IsIP() {
			actual.IP = testCase.Input.IP()
		} else {
			actual.Domain = testCase.Input.Domain()
		}

		if r := cmp.Diff(actual, testCase.Output); r != "" {
			t.Error("for input: ", testCase.Input, ":", r)
		}
	}
}

func TestAppendIP(t *testing.T) {
	for _, tc := range []struct {
		address Address
		want    []byte
	}{
		{ParseAddress("1.2.3.4"), []byte{0xff, 1, 2, 3, 4}},
		{ParseAddress("::ffff:1.2.3.4"), []byte{0xff, 1, 2, 3, 4}},
		{ParseAddress("2001:db8::1"), []byte{0xff, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{DomainAddress("example.com"), []byte{0xff}},
	} {
		if r := cmp.Diff(AppendIP([]byte{0xff}, tc.address), tc.want); r != "" {
			t.Errorf("AppendIP(%v): %s", tc.address, r)
		}
		appendIP := func() { AppendIP(make([]byte, 0, IPv6len), tc.address) }
		if n := testing.AllocsPerRun(100, appendIP); n != 0 {
			t.Errorf("AppendIP(%v): %v allocs", tc.address, n)
		}
	}

	// An Address implemented outside this package falls back to its IP().
	foreign := struct{ Address }{ParseAddress("5.6.7.8")}
	if r := cmp.Diff(AppendIP(nil, foreign), []byte{5, 6, 7, 8}); r != "" {
		t.Errorf("AppendIP(foreign address): %s", r)
	}
}

func TestInvalidAddressConvertion(t *testing.T) {
	panics := func(f func()) (ret bool) {
		defer func() {
			if r := recover(); r != nil {
				ret = true
			}
		}()
		f()
		return false
	}

	testCases := []func(){
		func() { ParseAddress("8.8.8.8").Domain() },
		func() { ParseAddress("2001:4860:0:2001::68").Domain() },
		func() { ParseAddress("example.com").IP() },
	}
	for idx, testCase := range testCases {
		if !panics(testCase) {
			t.Error("case ", idx, " failed")
		}
	}
}

func BenchmarkParseAddressIPv4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		addr := ParseAddress("8.8.8.8")
		if addr.Family() != AddressFamilyIPv4 {
			panic("not ipv4")
		}
	}
}

func BenchmarkParseAddressIPv6(b *testing.B) {
	for i := 0; i < b.N; i++ {
		addr := ParseAddress("2001:4860:0:2001::68")
		if addr.Family() != AddressFamilyIPv6 {
			panic("not ipv6")
		}
	}
}

func BenchmarkParseAddressDomain(b *testing.B) {
	for i := 0; i < b.N; i++ {
		addr := ParseAddress("example.com")
		if addr.Family() != AddressFamilyDomain {
			panic("not domain")
		}
	}
}
