package reverse_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/proxy/vless/reverse"
	"github.com/xtls/xray-core/transport"
)

func TestPublicEndpointEmpty(t *testing.T) {
	endpoint := reverse.NewPublicEndpoint("", nil)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.UDPDestination(net.DomainAddress("reverse"), 0),
	}})
	s := multiplex.NewSession(ctx, &transport.Link{Writer: buf.Discard})
	err := endpoint.Admit(ctx, s)
	if err == nil {
		t.Error("expected error, but nil")
	}
	if s.ID != 0 {
		t.Error("expected unadmitted session, but wire ID assigned")
	}
}
