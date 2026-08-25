package http

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func outboundContext(ctx context.Context) context.Context {
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target: net.TCPDestination(net.ParseAddress("203.0.113.7"), 443),
	}})
}

func filled(t *testing.T, ctx context.Context, header []*Header) map[string]string {
	t.Helper()
	out, err := fillRequestHeader(ctx, header)
	if err != nil {
		t.Fatalf("fillRequestHeader: %v", err)
	}
	values := make(map[string]string, len(out))
	for _, h := range out {
		values[h.Key] = h.Value
	}
	return values
}

// A health check dispatched through tagged.Dialer carries no inbound, which
// used to make every outbound with a configured "headers" map fail to build
// its request.
func TestFillRequestHeaderWithoutInbound(t *testing.T) {
	values := filled(t, outboundContext(context.Background()), []*Header{
		{Key: "Host", Value: "front.example.com:443"},
		{Key: "X-Source", Value: "{{.Source}}"},
		{Key: "X-Target", Value: "{{.Target}}"},
	})

	if values["Host"] != "front.example.com:443" {
		t.Errorf("Host = %q", values["Host"])
	}
	if values["X-Source"] != "tcp:0.0.0.0:0" {
		t.Errorf("X-Source = %q, want an unspecified source", values["X-Source"])
	}
	if values["X-Target"] != "tcp:203.0.113.7:443" {
		t.Errorf("X-Target = %q", values["X-Target"])
	}
}

func TestFillRequestHeaderWithInbound(t *testing.T) {
	ctx := session.ContextWithInbound(outboundContext(context.Background()), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("192.0.2.9"), 1234),
	})

	values := filled(t, ctx, []*Header{{Key: "X-Source", Value: "{{.Source}}"}})
	if values["X-Source"] != "tcp:192.0.2.9:1234" {
		t.Errorf("X-Source = %q", values["X-Source"])
	}
}

func TestFillRequestHeaderWithoutHeaders(t *testing.T) {
	out, err := fillRequestHeader(context.Background(), nil)
	if err != nil {
		t.Fatalf("fillRequestHeader: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %v, want nothing", out)
	}
}
