package internet_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	proxymanoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type dialerEchoHandler struct {
	outbound.Handler
	tag   string
	calls chan session.Outbound
}

func (h *dialerEchoHandler) Tag() string  { return h.tag }
func (h *dialerEchoHandler) Start() error { return nil }
func (h *dialerEchoHandler) Close() error { return nil }
func (h *dialerEchoHandler) Dispatch(ctx context.Context, link *transport.Link) {
	obs := session.OutboundsFromContext(ctx)
	h.calls <- *obs[len(obs)-1]
	defer common.Close(link.Writer)
	defer common.Interrupt(link.Reader)
	buf.Copy(link.Reader, link.Writer)
}

func setupDialerBalancer(t *testing.T) (*proxymanoutbound.Manager, *router.Router, chan session.Outbound) {
	t.Helper()
	m, err := proxymanoutbound.New(context.Background(), &proxyman.OutboundConfig{})
	common.Must(err)
	calls := make(chan session.Outbound, 32)
	for _, tag := range []string{"entry-a", "entry-b", "entry-c", "exit"} {
		common.Must(m.AddHandler(context.Background(), &dialerEchoHandler{tag: tag, calls: calls}))
	}
	r := new(router.Router)
	common.Must(r.Init(context.Background(), &router.Config{
		BalancingRule: []*router.BalancingRule{{
			Tag: "entries", OutboundSelector: []string{"entry-a", "entry-b", "entry-c"}, Strategy: "roundRobin",
		}},
	}, nil, m, nil))
	internet.InitSystemDialer(nil, m, r)
	t.Cleanup(func() {
		internet.InitSystemDialer(nil, nil, nil)
		common.Must(r.Close())
		common.Must(m.Close())
	})
	return m, r, calls
}

func TestDialerProxyBalancerSelectsPerConnection(t *testing.T) {
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		t.Run(network.String(), func(t *testing.T) {
			_, _, calls := setupDialerBalancer(t)
			dest := net.Destination{Network: network, Address: net.DomainAddress("exit.example"), Port: 443}
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: "exit"}})
			sockopt := &internet.SocketConfig{DialerProxy: "entries"}
			for i := 0; i < 6; i++ {
				conn, err := internet.DialSystem(ctx, dest, sockopt)
				common.Must(err)
				// Reusing the same connection does not advance the balancer.
				for j := 0; j < 2; j++ {
					_, err = conn.Write([]byte("ping"))
					common.Must(err)
					result := make([]byte, 4)
					_, err = io.ReadFull(conn, result)
					common.Must(err)
					if string(result) != "ping" {
						t.Fatal(string(result))
					}
				}
				common.Must(conn.Close())
				call := <-calls
				if want := []string{"entry-a", "entry-b", "entry-c"}[i%3]; call.Tag != want || call.Target != dest {
					t.Fatalf("got %+v, want %s to %s", call, want, dest)
				}
				select {
				case extra := <-calls:
					t.Fatalf("connection reuse dispatched again: %+v", extra)
				default:
				}
			}
			if sockopt.DialerProxy != "entries" {
				t.Fatal("shared socket settings were mutated")
			}
		})
	}
}

func TestDialerProxyOutboundPrecedesBalancer(t *testing.T) {
	m, _, calls := setupDialerBalancer(t)
	common.Must(m.AddHandler(context.Background(), &dialerEchoHandler{tag: "entries", calls: calls}))
	conn, err := internet.DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, 443), &internet.SocketConfig{DialerProxy: "entries"})
	common.Must(err)
	common.Must(conn.Close())
	if call := <-calls; call.Tag != "entries" {
		t.Fatal(call.Tag)
	}
}

func TestDialerProxyBalancerErrors(t *testing.T) {
	for _, test := range []struct{ name, target, want string }{
		{"missing", "missing", "balancer missing not found"},
		{"empty", "entries", "balancing strategy returns empty tag"},
		{"missing selected outbound", "entries", "there is no outbound handler"},
		{"cycle", "entries", "dialerProxy cycle: exit"},
		{"default router", "entries", "there is no outbound handler"},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, r, calls := setupDialerBalancer(t)
			switch test.name {
			case "empty":
				for _, tag := range []string{"entry-a", "entry-b", "entry-c"} {
					common.Must(m.RemoveHandler(context.Background(), tag))
				}
			case "missing selected outbound":
				common.Must(r.SetOverrideTarget("entries", "deleted"))
			case "cycle":
				common.Must(r.SetOverrideTarget("entries", "exit"))
			case "default router":
				internet.InitSystemDialer(nil, m, routing.DefaultRouter{})
			}
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: "exit"}})
			conn, err := internet.DialSystem(ctx, net.TCPDestination(net.LocalHostIP, 443), &internet.SocketConfig{DialerProxy: test.target})
			if conn != nil {
				conn.Close()
				t.Fatal("unexpected connection")
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want %s", err, test.want)
			}
			select {
			case call := <-calls:
				t.Fatalf("error silently dispatched: %+v", call)
			default:
			}
		})
	}
}
