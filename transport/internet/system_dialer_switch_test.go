package internet_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
)

type observedSystemDialer struct {
	internet.SystemDialer
	entered  chan struct{}
	returned chan error
}

func (d *observedSystemDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, options *internet.SocketConfig) (xnet.Conn, error) {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	conn, err := d.SystemDialer.Dial(ctx, src, dest, options)
	select {
	case d.returned <- err:
	default:
	}
	return conn, err
}

func TestEncryptedResolverUsesCurrentAdapterAfterSettingsBuild(t *testing.T) {
	for _, protocol := range []string{"tls", "https", "quic", "https+h3"} {
		for _, transition := range []struct {
			name          string
			initial       string
			runtimeLegacy bool
		}{
			{name: "context-to-legacy", initial: "context", runtimeLegacy: true},
			{name: "legacy-to-context", initial: "legacy"},
			{name: "default-to-legacy", initial: "default", runtimeLegacy: true},
		} {
			t.Run(protocol+"/"+transition.name, func(t *testing.T) {
				release := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				var legacyCalls, contextCalls atomic.Int32
				legacy := &systemLegacyAdapter{dial: func(string, string) (net.Conn, error) {
					legacyCalls.Add(1)
					<-release
					return nil, errors.New("legacy adapter released")
				}}
				cancellable := &systemContextAdapter{systemLegacyAdapter: legacy, dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					contextCalls.Add(1)
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-release:
						return nil, errors.New("context adapter released")
					}
				}}
				runtime := internet.WithAdapter(cancellable)
				if transition.runtimeLegacy {
					runtime = internet.WithAdapter(legacy)
				}
				switch transition.initial {
				case "context":
					internet.UseAlternativeSystemDialer(internet.WithAdapter(cancellable))
				case "legacy":
					internet.UseAlternativeSystemDialer(internet.WithAdapter(legacy))
				case "default":
					internet.UseAlternativeSystemDialer(nil)
				}
				t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
				t.Cleanup(unblock)
				address := "127.0.0.1:853"
				if protocol == "https" || protocol == "https+h3" {
					address = "https://127.0.0.1/dns-query"
				}
				settings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{Udpmasks: []*serial.TypedMessage{serial.ToTypedMessage(systemAdapterTestMask(protocol, address))}})
				if err != nil {
					t.Fatal(err)
				}
				observed := &observedSystemDialer{SystemDialer: runtime, entered: make(chan struct{}, 64), returned: make(chan error, 64)}
				internet.UseAlternativeSystemDialer(observed)
				conn, err := settings.FinalMask.DialUDP(t.Context(), xnet.UDPDestination(xnet.LocalHostIP, 443))
				if err != nil {
					t.Fatalf("settings built with previous adapter prevented runtime resolver: %v", err)
				}
				t.Cleanup(func() { unblock(); conn.Close() })
				if _, err := conn.Write([]byte("trigger runtime adapter")); err != nil {
					t.Fatal(err)
				}
				select {
				case <-observed.entered:
				case <-time.After(time.Second):
					t.Fatal("resolver exchange did not reach current dialer")
				}
				if transition.runtimeLegacy {
					select {
					case err := <-observed.returned:
						if err == nil {
							t.Fatal("legacy adapter was accepted for strict dial")
						}
					case <-time.After(time.Second):
						t.Fatal("strict dial entered a blocking legacy adapter")
					}
				}
				closed := make(chan error, 1)
				go func() { closed <- conn.Close() }()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("resolver Close did not finish")
				}
				if !transition.runtimeLegacy {
					select {
					case err := <-observed.returned:
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("runtime context dial returned %v", err)
						}
					case <-time.After(time.Second):
						t.Fatal("context adapter was not canceled")
					}
					if contextCalls.Load() == 0 {
						t.Fatal("runtime context adapter was not entered")
					}
				}
				if legacyCalls.Load() != 0 {
					t.Fatalf("encrypted resolver entered legacy Dial %d times", legacyCalls.Load())
				}
			})
		}
	}
}
