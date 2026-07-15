package mux_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	commonxudp "github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func waitForCondition(t *testing.T, timeout time.Duration, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func newLinkPair() (*transport.Link, *transport.Link) {
	opt := pipe.WithoutSizeLimit()
	uplinkReader, uplinkWriter := pipe.New(opt)
	downlinkReader, downlinkWriter := pipe.New(opt)

	uplink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	downlink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	return uplink, downlink
}

type TestDispatcher struct {
	OnDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *TestDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.OnDispatch(ctx, dest)
}

func (d *TestDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	return nil
}

func (d *TestDispatcher) Start() error {
	return nil
}

func (d *TestDispatcher) Close() error {
	return nil
}

func (*TestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestRegressionOutboundLeak(t *testing.T) {
	originalOutbounds := []*session.Outbound{{}}
	serverCtx := session.ContextWithOutbounds(context.Background(), originalOutbounds)

	websiteUplink, websiteDownlink := newLinkPair()

	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			// emulate what DefaultRouter.Dispatch does, and mutate something on the context
			ob := session.OutboundsFromContext(ctx)[0]
			ob.Target = dest
			return websiteDownlink, nil
		},
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	_, err := mux.NewServerWorker(serverCtx, &dispatcher, muxServerUplink)
	common.Must(err)

	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	common.Must(err)

	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})

	muxClientUplink, muxClientDownlink := newLinkPair()

	ok := client.Dispatch(clientCtx, muxClientUplink)
	if !ok {
		t.Error("failed to dispatch")
	}

	{
		b := buf.FromBytes([]byte("hello"))
		common.Must(muxClientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err := websiteUplink.Reader.ReadMultiBuffer()
	common.Must(err)
	res := resMb.String()
	if res != "hello" {
		t.Error("upload: ", res)
	}

	{
		b := buf.FromBytes([]byte("world"))
		common.Must(websiteUplink.Writer.WriteMultiBuffer(buf.MultiBuffer{b}))
	}

	resMb, err = muxClientDownlink.Reader.ReadMultiBuffer()
	common.Must(err)
	res = resMb.String()
	if res != "world" {
		t.Error("download: ", res)
	}

	outbounds := session.OutboundsFromContext(serverCtx)
	if outbounds[0] != originalOutbounds[0] {
		t.Error("outbound got reassigned: ", outbounds[0])
	}

	if outbounds[0].Target.Address != nil {
		t.Error("outbound target got leaked: ", outbounds[0].Target.String())
	}
}

func TestLogicalSessionReleasesOnlineIPWhileCarrierRemainsOpen(t *testing.T) {
	const sourceIP = "198.51.100.10"

	online := appstats.NewOnlineMap()
	websiteUplink, websiteDownlink := newLinkPair()
	t.Cleanup(func() {
		common.Close(websiteUplink.Reader)
		common.Close(websiteUplink.Writer)
	})

	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			online.AddIP(sourceIP)
			context.AfterFunc(ctx, func() { online.RemoveIP(sourceIP) })
			return websiteDownlink, nil
		},
	}

	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	t.Cleanup(cancelCarrier)
	muxServerUplink, muxServerDownlink := newLinkPair()
	server, err := mux.NewServerWorker(carrierCtx, &dispatcher, muxServerUplink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(server) })

	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(client) })

	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	muxClientUplink, muxClientDownlink := newLinkPair()
	if !client.Dispatch(clientCtx, muxClientUplink) {
		t.Fatal("failed to dispatch logical Mux session")
	}

	waitForCondition(t, time.Second, "online IP acquisition", func() bool {
		return online.Count() == 1
	})

	if err := common.Close(muxClientDownlink.Writer); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, time.Second, "logical Mux session close", func() bool {
		return server.ActiveConnections() == 0
	})
	if server.Closed() {
		t.Fatal("Mux carrier closed before online lifecycle assertion")
	}

	waitForCondition(t, 200*time.Millisecond, "online IP release while Mux carrier remains open", func() bool {
		return online.Count() == 0
	})
}

func TestMuxCarrierWithoutLogicalSessionDoesNotTrackOnlineIP(t *testing.T) {
	var dispatches atomic.Int32
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			dispatches.Add(1)
			return nil, errors.New("unexpected logical dispatch")
		},
	}

	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	t.Cleanup(cancelCarrier)
	muxServerUplink, _ := newLinkPair()
	server, err := mux.NewServerWorker(carrierCtx, &dispatcher, muxServerUplink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(server) })

	time.Sleep(20 * time.Millisecond)
	if dispatches.Load() != 0 {
		t.Fatalf("Mux control carrier triggered %d logical dispatches", dispatches.Load())
	}
}

func TestOnlineIPRemainsUntilLastLogicalSessionCloses(t *testing.T) {
	const sourceIP = "198.51.100.13"

	online := appstats.NewOnlineMap()
	var websitesMu sync.Mutex
	var websites []*transport.Link
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			online.AddIP(sourceIP)
			context.AfterFunc(ctx, func() { online.RemoveIP(sourceIP) })
			websiteUplink, websiteDownlink := newLinkPair()
			websitesMu.Lock()
			websites = append(websites, websiteUplink)
			websitesMu.Unlock()
			return websiteDownlink, nil
		},
	}
	t.Cleanup(func() {
		websitesMu.Lock()
		defer websitesMu.Unlock()
		for _, website := range websites {
			common.Close(website.Reader)
			common.Close(website.Writer)
		}
	})

	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	t.Cleanup(cancelCarrier)
	muxServerUplink, muxServerDownlink := newLinkPair()
	server, err := mux.NewServerWorker(carrierCtx, &dispatcher, muxServerUplink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(server) })
	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(client) })

	openSession := func(domain string) *transport.Link {
		t.Helper()
		clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.DomainAddress(domain), 80),
		}})
		uplink, downlink := newLinkPair()
		if !client.Dispatch(clientCtx, uplink) {
			t.Fatal("failed to dispatch logical Mux session")
		}
		if err := downlink.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}); err != nil {
			t.Fatal(err)
		}
		return downlink
	}
	first := openSession("one.example.com")
	second := openSession("two.example.com")

	waitForCondition(t, time.Second, "two online logical sessions", func() bool {
		return server.ActiveConnections() == 2 && online.Count() == 1
	})
	if err := common.Close(first.Writer); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, time.Second, "first logical session close", func() bool {
		return server.ActiveConnections() == 1
	})
	if online.Count() != 1 {
		t.Fatal("online IP was removed while another logical session remained active")
	}
	if err := common.Close(second.Writer); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, time.Second, "final logical session release", func() bool {
		return server.ActiveConnections() == 0 && online.Count() == 0
	})
}

func TestFailedLogicalDispatchReleasesOnlineIP(t *testing.T) {
	const sourceIP = "198.51.100.12"

	online := appstats.NewOnlineMap()
	acquired := make(chan struct{})
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			online.AddIP(sourceIP)
			context.AfterFunc(ctx, func() { online.RemoveIP(sourceIP) })
			close(acquired)
			return nil, errors.New("expected dispatch failure")
		},
	}

	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	t.Cleanup(cancelCarrier)
	muxServerUplink, muxServerDownlink := newLinkPair()
	server, err := mux.NewServerWorker(carrierCtx, &dispatcher, muxServerUplink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(server) })

	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(client) })

	clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	muxClientUplink, muxClientDownlink := newLinkPair()
	if !client.Dispatch(clientCtx, muxClientUplink) {
		t.Fatal("failed to create logical Mux session")
	}
	if err := muxClientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for failed dispatch")
	}
	waitForCondition(t, 200*time.Millisecond, "online IP release after failed dispatch", func() bool {
		return online.Count() == 0
	})
}

func TestFailedXUDPDispatchReleasesOnlineIP(t *testing.T) {
	const sourceIP = "198.51.100.14"

	online := appstats.NewOnlineMap()
	acquired := make(chan struct{})
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			online.AddIP(sourceIP)
			context.AfterFunc(ctx, func() { online.RemoveIP(sourceIP) })
			close(acquired)
			return nil, errors.New("expected XUDP dispatch failure")
		},
	}

	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	t.Cleanup(cancelCarrier)
	muxServerUplink, muxServerDownlink := newLinkPair()
	server, err := mux.NewServerWorker(carrierCtx, &dispatcher, muxServerUplink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(server) })
	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(client) })

	clientCtx := context.WithValue(context.Background(), "cone", true)
	clientCtx = session.ContextWithInbound(clientCtx, &session.Inbound{
		Name:   "socks",
		Source: net.UDPDestination(net.ParseAddress(sourceIP), 12345),
	})
	target := net.UDPDestination(net.DomainAddress("dns.example.com"), 53)
	clientCtx = session.ContextWithOutbounds(clientCtx, []*session.Outbound{{Target: target}})
	globalID := commonxudp.GetGlobalID(clientCtx)

	muxClientUplink, muxClientDownlink := newLinkPair()
	if !client.Dispatch(clientCtx, muxClientUplink) {
		t.Fatal("failed to create XUDP Mux session")
	}
	packet := buf.FromBytes([]byte("query"))
	packet.UDP = &target
	if err := muxClientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for failed XUDP dispatch")
	}
	waitForCondition(t, 200*time.Millisecond, "online IP release after failed XUDP dispatch", func() bool {
		return online.Count() == 0
	})
	mux.XUDPManager.Lock()
	_, retained := mux.XUDPManager.Map[globalID]
	mux.XUDPManager.Unlock()
	if retained {
		t.Fatal("failed XUDP dispatch retained a global flow entry")
	}
}

func TestXUDPReleasesOnlineIPWhenReusableFlowEnds(t *testing.T) {
	const sourceIP = "198.51.100.11"

	online := appstats.NewOnlineMap()
	var dispatches atomic.Int32
	websiteUplink, websiteDownlink := newLinkPair()
	t.Cleanup(func() {
		common.Close(websiteUplink.Reader)
		common.Close(websiteUplink.Writer)
	})

	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			dispatches.Add(1)
			online.AddIP(sourceIP)
			context.AfterFunc(ctx, func() { online.RemoveIP(sourceIP) })
			return websiteDownlink, nil
		},
	}

	carrierCtx, cancelCarrier := context.WithCancel(context.Background())
	t.Cleanup(cancelCarrier)
	muxServerUplink, muxServerDownlink := newLinkPair()
	server, err := mux.NewServerWorker(carrierCtx, &dispatcher, muxServerUplink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(server) })

	client, err := mux.NewClientWorker(*muxServerDownlink, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(client) })

	clientCtx := context.WithValue(context.Background(), "cone", true)
	clientCtx = session.ContextWithInbound(clientCtx, &session.Inbound{
		Name:   "socks",
		Source: net.UDPDestination(net.ParseAddress(sourceIP), 12345),
	})
	target := net.UDPDestination(net.DomainAddress("dns.example.com"), 53)
	clientCtx = session.ContextWithOutbounds(clientCtx, []*session.Outbound{{
		Target: target,
	}})
	globalID := commonxudp.GetGlobalID(clientCtx)
	if globalID == [8]byte{} {
		t.Fatal("expected non-empty XUDP global ID")
	}
	var registeredXUDP *mux.XUDP
	t.Cleanup(func() {
		mux.XUDPManager.Lock()
		if registeredXUDP != nil {
			delete(mux.XUDPManager.Map, registeredXUDP.GlobalID)
		}
		mux.XUDPManager.Unlock()
		if registeredXUDP != nil {
			registeredXUDP.Interrupt()
		}
	})

	muxClientUplink, muxClientDownlink := newLinkPair()
	if !client.Dispatch(clientCtx, muxClientUplink) {
		t.Fatal("failed to dispatch XUDP Mux session")
	}
	packet := buf.FromBytes([]byte("ping"))
	packet.UDP = &target
	if err := muxClientDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}

	waitForCondition(t, time.Second, "XUDP online IP acquisition", func() bool {
		return online.Count() == 1
	})
	waitForCondition(t, time.Second, "XUDP flow registration", func() bool {
		mux.XUDPManager.Lock()
		defer mux.XUDPManager.Unlock()
		for _, x := range mux.XUDPManager.Map {
			registeredXUDP = x
			return true
		}
		return false
	})

	if err := common.Close(muxClientDownlink.Writer); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, time.Second, "carrier-local XUDP session close", func() bool {
		return server.ActiveConnections() == 0
	})
	if online.Count() != 1 {
		t.Fatal("XUDP online reference was released before reusable flow ended")
	}
	if server.Closed() {
		t.Fatal("Mux carrier closed before XUDP lifecycle assertion")
	}
	if dispatches.Load() != 1 {
		t.Fatalf("unexpected initial XUDP dispatch count: %d", dispatches.Load())
	}

	reboundUplink, reboundDownlink := newLinkPair()
	if !client.Dispatch(clientCtx, reboundUplink) {
		t.Fatal("failed to rebind XUDP flow to another logical Mux session")
	}
	reboundPacket := buf.FromBytes([]byte("pong"))
	reboundPacket.UDP = &target
	if err := reboundDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{reboundPacket}); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, time.Second, "XUDP flow rebind", func() bool {
		return server.ActiveConnections() == 1
	})
	if dispatches.Load() != 1 {
		t.Fatalf("XUDP rebind created a second dispatched flow: %d", dispatches.Load())
	}
	if online.Count() != 1 {
		t.Fatalf("XUDP rebind changed online reference count: %d", online.Count())
	}
	if err := common.Close(reboundDownlink.Writer); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, time.Second, "rebound XUDP session close", func() bool {
		return server.ActiveConnections() == 0
	})

	mux.XUDPManager.Lock()
	x := registeredXUDP
	delete(mux.XUDPManager.Map, registeredXUDP.GlobalID)
	mux.XUDPManager.Unlock()
	if x == nil {
		t.Fatal("XUDP flow disappeared before permanent interruption")
	}
	x.Interrupt()

	waitForCondition(t, 200*time.Millisecond, "online IP release after XUDP flow interruption", func() bool {
		return online.Count() == 0
	})
}
