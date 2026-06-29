package http_test

import (
	"bufio"
	gonet "net"
	"net/http"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/common/protocol/http"
)

func TestApplyTrustedXForwardedFor(t *testing.T) {
	remoteAddr := &gonet.TCPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: 12345}

	t.Run("ignore X-Forwarded-For without trusted header", func(t *testing.T) {
		header := http.Header{}
		header.Add("X-Forwarded-For", "129.78.138.66, 129.78.64.103")

		if addr := ApplyTrustedXForwardedFor(header, nil, remoteAddr); addr != remoteAddr {
			t.Fatalf("unexpected remote address: %v", addr)
		}
	})

	t.Run("trust X-Forwarded-For", func(t *testing.T) {
		header := http.Header{}
		header.Add("X-Forwarded-For", "129.78.138.66, 129.78.64.103")
		header.Add("X-Trusted-CDN", "")

		addr := ApplyTrustedXForwardedFor(header, []string{"X-Trusted-CDN"}, remoteAddr)
		if addr.String() != "129.78.138.66:0" {
			t.Fatalf("unexpected remote address: %v", addr)
		}
	})

	t.Run("ignore non-IP X-Forwarded-For", func(t *testing.T) {
		header := http.Header{}
		header.Add("X-Forwarded-For", "example.com")
		header.Add("X-Trusted-CDN", "")

		if addr := ApplyTrustedXForwardedFor(header, []string{"X-Trusted-CDN"}, remoteAddr); addr != remoteAddr {
			t.Fatalf("unexpected remote address: %v", addr)
		}
	})
}

func TestHopByHopHeadersRemoving(t *testing.T) {
	rawRequest := `GET /pkg/net/http/ HTTP/1.1
Host: golang.org
Connection: keep-alive,Foo, Bar
Foo: foo
Bar: bar
Proxy-Connection: keep-alive
Proxy-Authenticate: abc
Accept-Encoding: gzip
Accept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7
Cache-Control: no-cache
Accept-Language: de,en;q=0.7,en-us;q=0.3

`
	b := bufio.NewReader(strings.NewReader(rawRequest))
	req, err := http.ReadRequest(b)
	common.Must(err)
	headers := []struct {
		Key   string
		Value string
	}{
		{
			Key:   "Foo",
			Value: "foo",
		},
		{
			Key:   "Bar",
			Value: "bar",
		},
		{
			Key:   "Connection",
			Value: "keep-alive,Foo, Bar",
		},
		{
			Key:   "Proxy-Connection",
			Value: "keep-alive",
		},
		{
			Key:   "Proxy-Authenticate",
			Value: "abc",
		},
	}
	for _, header := range headers {
		if v := req.Header.Get(header.Key); v != header.Value {
			t.Error("header ", header.Key, " = ", v, " want ", header.Value)
		}
	}

	RemoveHopByHopHeaders(req.Header)

	for _, header := range []string{"Connection", "Foo", "Bar", "Proxy-Connection", "Proxy-Authenticate"} {
		if v := req.Header.Get(header); v != "" {
			t.Error("header ", header, " = ", v)
		}
	}
}

func TestParseHost(t *testing.T) {
	testCases := []struct {
		RawHost     string
		DefaultPort net.Port
		Destination net.Destination
		Error       bool
	}{
		{
			RawHost:     "example.com:80",
			DefaultPort: 443,
			Destination: net.TCPDestination(net.DomainAddress("example.com"), 80),
		},
		{
			RawHost:     "tls.example.com",
			DefaultPort: 443,
			Destination: net.TCPDestination(net.DomainAddress("tls.example.com"), 443),
		},
		{
			RawHost:     "[2401:1bc0:51f0:ec08::1]:80",
			DefaultPort: 443,
			Destination: net.TCPDestination(net.ParseAddress("[2401:1bc0:51f0:ec08::1]"), 80),
		},
	}

	for _, testCase := range testCases {
		dest, err := ParseHost(testCase.RawHost, testCase.DefaultPort)
		if testCase.Error {
			if err == nil {
				t.Error("for test case: ", testCase.RawHost, " expected error, but actually nil")
			}
		} else {
			if dest != testCase.Destination {
				t.Error("for test case: ", testCase.RawHost, " expected host: ", testCase.Destination.String(), " but got ", dest.String())
			}
		}
	}
}
