package outbound

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet"
)

type guardedStreamProxy struct{ prepared, legacy bool }

func (p *guardedStreamProxy) Process(context.Context, *transport.Link, internet.Dialer) error {
	p.legacy = true
	return nil
}

func (p *guardedStreamProxy) PrepareStream(context.Context, *exchange.Stream, internet.Dialer) (exchange.Stream, error) {
	p.prepared = true
	return exchange.Stream{Reader: bytes.NewReader(nil), Writer: io.Discard}, nil
}

func TestStreamDispatchDoesNotEnterLegacyProcess(t *testing.T) {
	p := &guardedStreamProxy{}
	var _ proxy.StreamOutbound = p
	h := &Handler{proxy: p, policyManager: policy.DefaultManager{}}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	source := exchange.Stream{Reader: bytes.NewReader(nil), Writer: io.Discard}
	if err := h.DispatchStream(ctx, source); err != nil {
		t.Fatal(err)
	}
	if !p.prepared || p.legacy {
		t.Fatalf("prepared=%v legacy=%v", p.prepared, p.legacy)
	}
}
