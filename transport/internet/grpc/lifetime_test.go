package grpc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/grpc/connectivity"
)

func settings() *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{ProtocolName: "grpc", ProtocolSettings: &Config{ServiceName: "lifetime"}}
}

func cacheHas(s *internet.MemoryStreamConfig) bool {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	for k := range globalDialerMap {
		if k.MemoryStreamConfig == s {
			return true
		}
	}
	return false
}

func TestClientCacheCloseIsolation(t *testing.T) {
	a, b := settings(), settings()
	defer a.Close()
	defer b.Close()
	dest := net.TCPDestination(net.LocalHostIP, 1)
	ca, err := getGrpcClient(context.Background(), dest, a)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := getGrpcClient(context.Background(), net.TCPDestination(net.LocalHostIP, 2), a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := getGrpcClient(context.Background(), dest, b)
	if err != nil {
		t.Fatal(err)
	}
	again, err := getGrpcClient(context.Background(), dest, a)
	if err != nil || again != ca || ca == cb {
		t.Fatal("bad sharing boundary")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if ca.GetState() != connectivity.Shutdown || ca2.GetState() != connectivity.Shutdown || cacheHas(a) {
		t.Fatal("stopped owner retained its client")
	}
	if cb.GetState() == connectivity.Shutdown || !cacheHas(b) {
		t.Fatal("other owner was closed")
	}
	if c, err := getGrpcClient(context.Background(), dest, a); err == nil {
		c.Close()
		t.Fatal("closed owner resurrected")
	}
	if cacheHas(a) {
		t.Fatal("failed acquisition entered cache")
	}
}

func TestDialCreationRacesOwnerClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		s := settings()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				getGrpcClient(context.Background(), net.TCPDestination(net.LocalHostIP, 1), s)
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); <-start; s.Close() }()
		close(start)
		wg.Wait()
		s.Close()
		if cacheHas(s) {
			t.Fatal("racing acquisition survived close")
		}
	}
}

// The first hook gates Close after sealing but before the cache cleanup hook.
func TestDialWhileOwnerCleanupPending(t *testing.T) {
	s := settings()
	entered, release := make(chan struct{}), make(chan struct{})
	s.OnClose(func() error { close(entered); <-release; return nil })
	c, err := getGrpcClient(context.Background(), net.TCPDestination(net.LocalHostIP, 1), s)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	<-entered
	// Neither cached reuse nor creation may pass a sealed owner.
	if reused, err := getGrpcClient(context.Background(), net.TCPDestination(net.LocalHostIP, 1), s); err == nil {
		close(release)
		<-done
		reused.Close()
		t.Fatal("cached client issued after sealing")
	}
	// A different destination forces creation rather than a cached lookup.
	late, err := getGrpcClient(context.Background(), net.TCPDestination(net.LocalHostIP, 2), s)
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if err == nil {
		late.Close()
		t.Fatal("creation registered after sealing")
	}
	if c.GetState() != connectivity.Shutdown || cacheHas(s) {
		t.Fatal("cleanup did not finish")
	}
}

type observedDialer struct {
	block     bool
	calls     atomic.Int64
	started   chan struct{}
	cancelled chan struct{}
}

func (d *observedDialer) Dial(ctx context.Context, _ net.Address, _ net.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	d.calls.Add(1)
	select {
	case d.started <- struct{}{}:
	default:
	}
	if d.block {
		<-ctx.Done()
		close(d.cancelled)
		return nil, ctx.Err()
	}
	return nil, errors.New("synthetic unreachable endpoint")
}
func (*observedDialer) DestIpAddress() net.IP { return nil }
func TestCloseStopsInFlightDialAndBackoff(t *testing.T) {
	const caseEnv = "XRAY_GRPC_LIFETIME_DIAL_CASE"
	mode := os.Getenv(caseEnv)
	if mode == "" {
		for _, mode := range []string{"inflight", "backoff"} {
			t.Run(mode, func(t *testing.T) {
				// The system dialer is process-global. Isolate replacement from other
				// tests' asynchronously finishing transport dial goroutines.
				cmd := exec.Command(os.Args[0], "-test.run=^TestCloseStopsInFlightDialAndBackoff$", "-test.count=1", "-test.timeout=15s")
				cmd.Env = append(os.Environ(), caseEnv+"="+mode)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%v\n%s", err, output)
				}
			})
		}
		return
	}
	block := mode == "inflight"
	d := &observedDialer{block: block, started: make(chan struct{}, 16), cancelled: make(chan struct{})}
	// Installed before any client exists, and never replaced in this child.
	internet.UseAlternativeSystemDialer(d)
	s := settings()
	defer s.Close()
	c, err := getGrpcClient(context.Background(), net.TCPDestination(net.LocalHostIP, 1), s)
	if err != nil {
		t.Fatal(err)
	}
	wait := func() {
		select {
		case <-d.started:
		case <-time.After(3 * time.Second):
			t.Fatal("no dial")
		}
	}
	wait()
	if !block {
		wait()
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if block {
		select {
		case <-d.cancelled:
		case <-time.After(time.Second):
			t.Fatal("dial context not cancelled")
		}
	}
	before := d.calls.Load()
	time.Sleep(1200 * time.Millisecond)
	if d.calls.Load() != before || c.GetState() != connectivity.Shutdown || cacheHas(s) {
		t.Fatal("activity survived Close")
	}
}
