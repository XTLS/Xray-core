package http

import (
	"bufio"
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// connectRequest builds the request setUpHTTPTunnel starts from.
func connectRequest(target string) *http.Request {
	return &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Header: make(http.Header),
		Host:   target,
	}
}

func writeRequest(t *testing.T, req *http.Request) string {
	t.Helper()
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return buf.String()
}

func requestLine(t *testing.T, raw string) string {
	t.Helper()
	line, err := bufio.NewReader(strings.NewReader(raw)).ReadString('\n')
	if err != nil {
		t.Fatalf("read request line: %v", err)
	}
	return strings.TrimSpace(line)
}

// A configured Host must reach the wire. Request.Write ignores Header["Host"],
// so setting it there alone leaves the header at the tunnel target.
func TestApplyRequestHeadersSendsConfiguredHost(t *testing.T) {
	const target = "203.0.113.7:443"
	req := connectRequest(target)
	applyRequestHeaders(req, target, []*Header{
		{Key: "Host", Value: "front.example.com:443"},
		{Key: "X-Token", Value: "abc"},
	})

	raw := writeRequest(t, req)
	if !strings.Contains(raw, "Host: front.example.com:443\r\n") {
		t.Errorf("configured Host missing from request:\n%s", raw)
	}
	if !strings.Contains(raw, "X-Token: abc\r\n") {
		t.Errorf("other headers should still be applied:\n%s", raw)
	}
}

// For CONNECT, Request.Write derives the request-URI from req.Host, so a Host
// override must not drag the tunnel authority along with it.
func TestApplyRequestHeadersKeepsTheTunnelAuthority(t *testing.T) {
	const target = "203.0.113.7:443"
	req := connectRequest(target)
	applyRequestHeaders(req, target, []*Header{{Key: "Host", Value: "front.example.com:443"}})

	if got, want := requestLine(t, writeRequest(t, req)), "CONNECT "+target+" HTTP/1.1"; got != want {
		t.Errorf("request line = %q, want %q", got, want)
	}
}

func TestApplyRequestHeadersMatchesHostCaseInsensitively(t *testing.T) {
	const target = "203.0.113.7:443"
	req := connectRequest(target)
	applyRequestHeaders(req, target, []*Header{{Key: "host", Value: "front.example.com:443"}})

	if req.Host != "front.example.com:443" {
		t.Errorf("req.Host = %q, want the configured value", req.Host)
	}
}

func TestApplyRequestHeadersLeavesTheDefaultHostAlone(t *testing.T) {
	const target = "203.0.113.7:443"
	req := connectRequest(target)
	applyRequestHeaders(req, target, []*Header{{Key: "X-Token", Value: "abc"}})

	raw := writeRequest(t, req)
	if !strings.Contains(raw, "Host: "+target+"\r\n") {
		t.Errorf("without an override the Host should stay the target:\n%s", raw)
	}
	if got, want := requestLine(t, raw), "CONNECT "+target+" HTTP/1.1"; got != want {
		t.Errorf("request line = %q, want %q", got, want)
	}
}
