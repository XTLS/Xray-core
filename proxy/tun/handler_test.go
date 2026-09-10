package tun

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	apppolicy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
)

type testCounter struct {
	value int64
}

func (c *testCounter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *testCounter) Set(value int64) int64 {
	return atomic.SwapInt64(&c.value, value)
}

func (c *testCounter) Add(value int64) int64 {
	return atomic.AddInt64(&c.value, value) - value
}

type testConn struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func newTestConn(input []byte) *testConn {
	return &testConn{reader: bytes.NewReader(input)}
}

func (c *testConn) Read(payload []byte) (int, error) {
	return c.reader.Read(payload)
}

func (c *testConn) Write(payload []byte) (int, error) {
	return c.writer.Write(payload)
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}
}

func (c *testConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
}

func (c *testConn) SetDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(time.Time) error {
	return nil
}

type testDispatcher struct {
	writePayload []byte
	readBytes    int32
}

func (d *testDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (d *testDispatcher) Start() error {
	return nil
}

func (d *testDispatcher) Close() error {
	return nil
}

func (d *testDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	atomic.StoreInt32(&d.readBytes, mb.Len())
	buf.ReleaseMulti(mb)

	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(d.writePayload)})
}

func TestHandlerCountsTunConnectionTraffic(t *testing.T) {
	uplinkCounter := new(testCounter)
	downlinkCounter := new(testCounter)
	dispatcher := &testDispatcher{writePayload: []byte("downlink")}
	conn := newTestConn([]byte("uplink"))

	handler := &Handler{
		ctx:             context.Background(),
		config:          &Config{},
		dispatcher:      dispatcher,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := uplinkCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("unexpected uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("unexpected downlink counter: got %d, want %d", got, len("downlink"))
	}
	if got := int(atomic.LoadInt32(&dispatcher.readBytes)); got != len("uplink") {
		t.Fatalf("dispatcher read unexpected bytes: got %d, want %d", got, len("uplink"))
	}
	if got := conn.writer.String(); got != "downlink" {
		t.Fatalf("connection write mismatch: got %q, want %q", got, "downlink")
	}
}

type udpPacket struct {
	payload []byte
	source  xnet.Destination
	target  xnet.Destination
}

type udpEchoServer struct {
	conn     *net.UDPConn
	received chan []byte
	clients  chan *net.UDPAddr
}

func startUDPEchoServer(t *testing.T) *udpEchoServer {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server := &udpEchoServer{
		conn:     conn,
		received: make(chan []byte, 4),
		clients:  make(chan *net.UDPAddr, 4),
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buffer := make([]byte, 2048)
		for {
			n, client, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			payload := append([]byte(nil), buffer[:n]...)
			server.received <- payload
			server.clients <- client
			_, _ = conn.WriteToUDP(payload, client)
		}
	}()

	return server
}

func receiveUDPClient(t *testing.T, clients <-chan *net.UDPAddr) *net.UDPAddr {
	t.Helper()
	select {
	case client := <-clients:
		return client
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for UDP client address")
		return nil
	}
}

func (s *udpEchoServer) destination() xnet.Destination {
	address := s.conn.LocalAddr().(*net.UDPAddr)
	return xnet.UDPDestination(xnet.IPAddress(address.IP), xnet.Port(address.Port))
}

func startTunUDPTestHandler(t *testing.T, countUplink, countDownlink bool) *Handler {
	t.Helper()

	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&apppolicy.Config{System: &apppolicy.SystemPolicy{
				Stats: &apppolicy.SystemPolicy_Stats{
					InboundUplink:   countUplink,
					InboundDownlink: countDownlink,
				},
			}}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })

	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "tun-test"})
	handler := &Handler{config: &Config{}}
	if err := handler.Init(
		ctx,
		instance.GetFeature(policy.ManagerType()).(policy.Manager),
		instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
	); err != nil {
		t.Fatal(err)
	}
	if (handler.uplinkCounter != nil) != countUplink || (handler.downlinkCounter != nil) != countDownlink {
		t.Fatal("TUN inbound counters do not match the configured policy")
	}
	return handler
}

func receiveUDPPayload(t *testing.T, packets <-chan []byte) []byte {
	t.Helper()
	select {
	case payload := <-packets:
		return payload
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for UDP packet")
		return nil
	}
}

func receiveTunPacket(t *testing.T, packets <-chan udpPacket) udpPacket {
	t.Helper()
	select {
	case packet := <-packets:
		return packet
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TUN UDP packet")
		return udpPacket{}
	}
}

func requireCounterValue(t *testing.T, counter featurestats.Counter, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := counter.Value(); got == want {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("counter = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func newTunUDPTestConnectionHandler(t *testing.T, handler *Handler, writePacket func([]byte, xnet.Destination, xnet.Destination) error) *udpConnectionHandler {
	t.Helper()
	var cancel context.CancelFunc
	handler.ctx, cancel = context.WithCancel(handler.ctx)
	done := make(chan struct{})
	udpHandler := newUdpConnectionHandler(func(conn xnet.Conn, destination xnet.Destination) {
		handler.HandleConnection(conn, destination)
		close(done)
	}, writePacket)
	t.Cleanup(func() {
		udpHandler.RLock()
		connections := make([]*udpConn, 0, len(udpHandler.udpConns))
		for _, conn := range udpHandler.udpConns {
			connections = append(connections, conn)
		}
		udpHandler.RUnlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("timed out waiting for TUN UDP connection handler to stop")
		}
	})
	return udpHandler
}

func testTunUDPPacketDestinations(t *testing.T, countUplink, countDownlink bool) {
	t.Helper()

	serverA := startUDPEchoServer(t)
	serverB := startUDPEchoServer(t)

	replies := make(chan udpPacket, 4)
	handler := startTunUDPTestHandler(t, countUplink, countDownlink)
	udpHandler := newTunUDPTestConnectionHandler(t, handler, func(data []byte, source, target xnet.Destination) error {
		replies <- udpPacket{payload: append([]byte(nil), data...), source: source, target: target}
		return nil
	})

	source := xnet.UDPDestination(xnet.IPAddress(net.IPv4(10, 0, 0, 2)), 40000)
	packetA := []byte("packet-a")
	packetB := []byte("packet-b")
	udpHandler.HandlePacket(source, serverA.destination(), packetA)
	udpHandler.RLock()
	association := udpHandler.udpConns[source]
	udpHandler.RUnlock()
	if association == nil {
		t.Fatal("first packet did not create a production TUN UDP association")
	}
	if got := receiveUDPPayload(t, serverA.received); !bytes.Equal(got, packetA) {
		t.Fatalf("server A received %q, want %q", got, packetA)
	}
	replyA := receiveTunPacket(t, replies)
	if !bytes.Equal(replyA.payload, packetA) || replyA.source != serverA.destination() || replyA.target != source {
		t.Fatalf("first reply = %+v, want payload %q from %v to %v", replyA, packetA, serverA.destination(), source)
	}

	udpHandler.HandlePacket(source, serverB.destination(), packetB)
	udpHandler.RLock()
	reusedAssociation := udpHandler.udpConns[source]
	udpHandler.RUnlock()
	if reusedAssociation != association {
		t.Fatal("second packet did not reuse the production TUN UDP association")
	}
	secondServer := ""
	var secondPayload []byte
	select {
	case secondPayload = <-serverA.received:
		secondServer = "A"
	case secondPayload = <-serverB.received:
		secondServer = "B"
	case <-time.After(5 * time.Second):
		t.Fatal("neither UDP server received the second packet")
	}
	replyB := receiveTunPacket(t, replies)
	if secondServer != "B" || !bytes.Equal(secondPayload, packetB) {
		t.Errorf("second packet delivered to server %s with payload %q, want server B with %q", secondServer, secondPayload, packetB)
	}
	if !bytes.Equal(replyB.payload, packetB) || replyB.source != serverB.destination() || replyB.target != source {
		t.Errorf("second reply = %+v, want payload %q from %v to %v", replyB, packetB, serverB.destination(), source)
	}

	wantBytes := int64(len(packetA) + len(packetB))
	if countUplink {
		requireCounterValue(t, handler.uplinkCounter, wantBytes)
	}
	if countDownlink {
		requireCounterValue(t, handler.downlinkCounter, wantBytes)
	}
}

func TestTunUDPInboundStatsPreservePacketDestinations(t *testing.T) {
	tests := []struct {
		name          string
		countUplink   bool
		countDownlink bool
	}{
		{name: "stats_off"},
		{name: "uplink_only", countUplink: true},
		{name: "downlink_only", countDownlink: true},
		{name: "uplink_and_downlink", countUplink: true, countDownlink: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testTunUDPPacketDestinations(t, test.countUplink, test.countDownlink)
		})
	}
}

func testTunUDPDownlinkPacketSource(t *testing.T, countDownlink bool) {
	t.Helper()

	serverA := startUDPEchoServer(t)
	serverB := startUDPEchoServer(t)

	replies := make(chan udpPacket, 4)
	handler := startTunUDPTestHandler(t, false, countDownlink)
	udpHandler := newTunUDPTestConnectionHandler(t, handler, func(data []byte, source, target xnet.Destination) error {
		replies <- udpPacket{payload: append([]byte(nil), data...), source: source, target: target}
		return nil
	})

	source := xnet.UDPDestination(xnet.IPAddress(net.IPv4(10, 0, 0, 2)), 40000)
	packetA := []byte("from-a")
	packetB := []byte("from-b")
	udpHandler.HandlePacket(source, serverA.destination(), packetA)
	if got := receiveUDPPayload(t, serverA.received); !bytes.Equal(got, packetA) {
		t.Fatalf("server A received %q, want %q", got, packetA)
	}
	freedomClient := receiveUDPClient(t, serverA.clients)
	_ = receiveTunPacket(t, replies)

	if _, err := serverB.conn.WriteToUDP(packetB, freedomClient); err != nil {
		t.Fatal(err)
	}
	replyB := receiveTunPacket(t, replies)
	if !bytes.Equal(replyB.payload, packetB) || replyB.source != serverB.destination() || replyB.target != source {
		t.Errorf("reply from server B = %+v, want payload %q from %v to %v", replyB, packetB, serverB.destination(), source)
	}

	if countDownlink {
		wantBytes := int64(len(packetA) + len(packetB))
		requireCounterValue(t, handler.downlinkCounter, wantBytes)
	}
}

func TestTunUDPInboundDownlinkStatsPreservePacketSource(t *testing.T) {
	t.Run("stats_off", func(t *testing.T) {
		testTunUDPDownlinkPacketSource(t, false)
	})
	t.Run("downlink_only", func(t *testing.T) {
		testTunUDPDownlinkPacketSource(t, true)
	})
}

func newManagedUDPPacket(t *testing.T, payload []byte, destination xnet.Destination) *buf.Buffer {
	t.Helper()
	packet := buf.New()
	if _, err := packet.Write(payload); err != nil {
		packet.Release()
		t.Fatal(err)
	}
	packet.UDP = &destination
	return packet
}

func requireReleasedPackets(t *testing.T, packets ...*buf.Buffer) {
	t.Helper()
	for i, packet := range packets {
		if packet.Len() != 0 || packet.UDP != nil {
			t.Errorf("packet %d was not released", i)
		}
	}
}

func TestTunUDPStatsWriter(t *testing.T) {
	source := xnet.UDPDestination(xnet.IPAddress(net.IPv4(10, 0, 0, 2)), 40000)
	destinationA := xnet.UDPDestination(xnet.LocalHostIP, 10001)
	destinationB := xnet.UDPDestination(xnet.LocalHostIP, 10002)

	t.Run("success", func(t *testing.T) {
		counter := new(testCounter)
		var destinations []xnet.Destination
		conn := &udpConn{
			handler: &udpConnectionHandler{writePacket: func(data []byte, source, target xnet.Destination) error {
				destinations = append(destinations, source)
				return nil
			}},
			src: source,
			dst: destinationA,
		}
		writer := &tunUDPStatsWriter{writer: conn, counter: counter}
		first := newManagedUDPPacket(t, []byte("first"), destinationA)
		second := newManagedUDPPacket(t, []byte("second"), destinationB)
		empty := newManagedUDPPacket(t, nil, destinationA)

		if err := writer.WriteMultiBuffer(buf.MultiBuffer{first, second, empty}); err != nil {
			t.Fatal(err)
		}
		if got, want := counter.Value(), int64(len("first")+len("second")); got != want {
			t.Errorf("counter = %d, want %d", got, want)
		}
		if len(destinations) != 3 || destinations[0] != destinationA || destinations[1] != destinationB || destinations[2] != destinationA {
			t.Errorf("destinations = %v, want [%v %v %v]", destinations, destinationA, destinationB, destinationA)
		}
		requireReleasedPackets(t, first, second, empty)
	})

	t.Run("write_error", func(t *testing.T) {
		counter := new(testCounter)
		writeErr := errors.New("test write error")
		var destinations []xnet.Destination
		conn := &udpConn{
			handler: &udpConnectionHandler{writePacket: func(data []byte, source, target xnet.Destination) error {
				destinations = append(destinations, source)
				if len(destinations) == 2 {
					return writeErr
				}
				return nil
			}},
			src: source,
			dst: destinationA,
		}
		writer := &tunUDPStatsWriter{writer: conn, counter: counter}
		first := newManagedUDPPacket(t, []byte("first"), destinationA)
		second := newManagedUDPPacket(t, []byte("second"), destinationB)
		third := newManagedUDPPacket(t, []byte("third"), destinationA)

		if err := writer.WriteMultiBuffer(buf.MultiBuffer{first, second, third}); !errors.Is(err, writeErr) {
			t.Fatalf("error = %v, want %v", err, writeErr)
		}
		if got, want := counter.Value(), int64(len("first")); got != want {
			t.Errorf("counter = %d, want successful prefix %d", got, want)
		}
		if len(destinations) != 2 || destinations[0] != destinationA || destinations[1] != destinationB {
			t.Errorf("destinations = %v, want [%v %v]", destinations, destinationA, destinationB)
		}
		requireReleasedPackets(t, first, second, third)
	})
}
