package freedom

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func TestUnconditionalBlockFastPath(t *testing.T) {
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		t.Run(network.String(), func(t *testing.T) {
			const reply = "blocked"
			h := new(Handler)
			if err := h.Init(&Config{Firewall: []*FirewallConfig{{
				Action: RuleAction_Block,
				Delay:  &Range{},
				Reply:  &Reply{Type: "custom", CustomResponseData: []byte(reply)},
			}}}, nil); err != nil {
				t.Fatal(err)
			}
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
				Target: net.Destination{Network: network, Address: net.DomainAddress("blocked.invalid"), Port: 443},
			}})
			var output bytes.Buffer
			link := &transport.Link{
				Reader: buf.NewReader(bytes.NewReader(nil)),
				Writer: &buf.BufferToBytesWriter{Writer: &output},
			}
			// An unconditional block must finish without touching the dialer or resolving the domain.
			if err := h.Process(ctx, link, nil); err != nil {
				t.Fatal(err)
			}
			if output.String() != reply {
				t.Fatalf("reply = %q, want %q", output.String(), reply)
			}
		})
	}
}

func TestFirewallReply(t *testing.T) {
	custom := bytes.Repeat([]byte("custom response"), buf.Size)
	for _, test := range []struct {
		name  string
		reply *Reply
		want  []byte
	}{
		{name: "default"},
		{name: "none", reply: &Reply{Type: "none"}},
		{name: "http", reply: &Reply{Type: "http"}},
		{name: "custom", reply: &Reply{Type: "custom", CustomResponseData: custom}, want: custom},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule, err := buildRule(&FirewallConfig{
				Action: RuleAction_Block,
				Delay:  &Range{},
				Reply:  test.reply,
			})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			dest := net.TCPDestination(net.LocalHostIP, 80)
			if err := new(Handler).blackhole(context.Background(), buf.NewReader(bytes.NewReader(nil)), &buf.BufferToBytesWriter{Writer: &output}, rule, &dest); err != nil {
				t.Fatal(err)
			}
			if test.name == "http" {
				response, err := http.ReadResponse(bufio.NewReader(&output), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusForbidden {
					t.Fatalf("HTTP status = %d, want 403", response.StatusCode)
				}
			} else if !bytes.Equal(output.Bytes(), test.want) {
				t.Fatalf("reply has %d bytes, want %d", output.Len(), len(test.want))
			}
		})
	}
}
