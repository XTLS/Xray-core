package grpc_test

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	fout "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type lookupGate struct {
	fout.Manager
	entered, release, attempted, returned chan struct{}
}

func (m *lookupGate) GetHandler(tag string) fout.Handler {
	if tag == "relay" {
		close(m.entered)
		<-m.release
		close(m.attempted)
		h := m.Manager.GetHandler(tag) // The actual Manager read lock.
		close(m.returned)
		return h
	}
	return m.Manager.GetHandler(tag)
}

type closeGateHandler struct {
	tag              string
	entered, release chan struct{}
	once             sync.Once
}

func (h *closeGateHandler) Tag() string                        { return h.tag }
func (*closeGateHandler) Start() error                         { return nil }
func (*closeGateHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*closeGateHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (*closeGateHandler) Dispatch(_ context.Context, link *transport.Link) {
	common.Close(link.Reader)
	common.Close(link.Writer)
}

func (h *closeGateHandler) Close() error {
	if h.entered != nil {
		h.once.Do(func() { close(h.entered) })
		<-h.release
	}
	return nil
}

// Force a pending dialerProxy lookup to contend with Manager.Close's write
// lock, after gRPC cleanup has run but before that lock is released.
func TestCoreCloseWhileDialerProxyLookupPending(t *testing.T) {
	const childEnv = "XRAY_GRPC_PROXY_CLOSE_CHILD"
	if os.Getenv(childEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCoreCloseWhileDialerProxyLookupPending$", "-test.count=1", "-test.timeout=12s")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, output)
		}
		return
	}
	// Isolated process: InitSystemDialer's process-global manager is not
	// replaced concurrently with another test's late dial goroutines.
	v, d := configuredCoreWithProxy(t, false, "relay")
	m := v.GetFeature(fout.ManagerType()).(fout.Manager)
	lookup := &lookupGate{Manager: m, entered: make(chan struct{}), release: make(chan struct{}), attempted: make(chan struct{}), returned: make(chan struct{})}
	hold := &closeGateHandler{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseLookup, releaseClose sync.Once
	defer func() {
		releaseLookup.Do(func() { close(lookup.release) })
		releaseClose.Do(func() { close(hold.release) })
	}()
	if err := m.AddHandler(context.Background(), &closeGateHandler{tag: "relay"}); err != nil {
		t.Fatal(err)
	}
	// Untagged handlers close after all tagged handlers. Once this one is
	// reached, the gRPC Handler.Close has finished while m.access is held.
	if err := m.AddHandler(context.Background(), hold); err != nil {
		t.Fatal(err)
	}
	internet.InitSystemDialer(nil, lookup)
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	dialDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		c, err := d.Dial(session.ContextWithOutbounds(ctx, []*session.Outbound{{}}), xnet.TCPDestination(xnet.LocalHostIP, 1))
		if c != nil {
			c.Close()
		}
		dialDone <- err
	}()
	await := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatal(what)
		}
	}
	await(lookup.entered, "dial never reached dialerProxy GetHandler")
	closeDone := make(chan error, 1)
	go func() { closeDone <- v.Close() }()
	await(hold.entered, "gRPC close blocked behind pending dialerProxy lookup")
	releaseLookup.Do(func() { close(lookup.release) })
	await(lookup.attempted, "lookup did not attempt Manager read lock")
	select {
	case <-lookup.returned:
		t.Fatal("lookup passed the held Manager write lock")
	case <-time.After(20 * time.Millisecond):
	}
	releaseClose.Do(func() { close(hold.release) })
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("core Close deadlocked")
	}
	await(lookup.returned, "lookup did not finish after Manager unlock")
	select {
	case err := <-dialDone:
		if err == nil {
			t.Fatal("closing core unexpectedly established stream")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending RPC did not end")
	}
}
