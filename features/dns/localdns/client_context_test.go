package localdns

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

func TestLocalDNSLookupIPContextCancelsResolver(t *testing.T) {
	for _, controllers := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard", true: "controllers"}[controllers], func(t *testing.T) {
			started := make(chan struct{}, 1)
			canceled := make(chan struct{}, 1)
			release := make(chan struct{})
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-ctx.Done():
					select {
					case canceled <- struct{}{}:
					default:
					}
					return nil, ctx.Err()
				case <-release:
					return nil, errors.New("test released")
				}
			}}
			standard, common, previous := net.DefaultResolver, xnet.DefaultResolver, internet.Controllers
			net.DefaultResolver, xnet.DefaultResolver, internet.Controllers = resolver, resolver, nil
			if controllers {
				internet.Controllers = []func(string, string, syscall.RawConn) error{func(string, string, syscall.RawConn) error { return nil }}
			}
			t.Cleanup(func() {
				close(release)
				net.DefaultResolver, xnet.DefaultResolver, internet.Controllers = standard, common, previous
			})
			client := New()
			if controllers {
				client.r = resolver
				wrong := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
					t.Error("controller lookup used default resolver")
					return nil, errors.New("wrong resolver")
				}}
				net.DefaultResolver, xnet.DefaultResolver = wrong, wrong
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, _, err := client.LookupIPContext(ctx, "blocked-local.xdns-test.invalid", featureDNS.IPOption{IPv4Enable: true})
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("system DNS lookup did not start")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("local client ignored cancellation")
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("underlying system DNS worker was not canceled")
			}
		})
	}
}

func TestLocalDNSLookupIPContextLiteralAndCanceled(t *testing.T) {
	client := New()
	for _, lookup := range []func(string, featureDNS.IPOption) ([]xnet.IP, uint32, error){client.LookupIP, func(host string, option featureDNS.IPOption) ([]xnet.IP, uint32, error) {
		return client.LookupIPContext(t.Context(), host, option)
	}} {
		ips, ttl, err := lookup("127.0.0.1", featureDNS.IPOption{IPv4Enable: true})
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) || ttl != featureDNS.DefaultTTL {
			t.Fatalf("local lookup = %v, %d, %v", ips, ttl, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := client.LookupIPContext(ctx, "127.0.0.1", featureDNS.IPOption{IPv4Enable: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled lookup returned %v", err)
	}
}
